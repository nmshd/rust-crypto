use std::any::Any;
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{
                    AsymmetricEncryption,
                    EccSchemeAlgorithm,
                    BlockCiphers,
                    EccCurves,
                    SymmetricMode
                },
                KeyBits
            }
        },
        error::SecurityModuleError,
        traits::module_provider::Provider,
    },
    tpm::{
        android::{
            knox::{
                KnoxProvider,
                interface::jni::RustDef
            }
        },
        core::error::TpmError::UnsupportedOperation
    }
};
use tracing::instrument;


/// Implements the `Provider` trait, providing cryptographic operations utilizing a TPM.
///
/// This implementation is specific to Samsung Knox Vault and uses it for all cryptographic operations
/// In theory, this should also work for other TPMs on Android phones, but it is only tested with Samsung Knox Vault
impl Provider for KnoxProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    ///  and stored in Knox Vault.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `Box<dyn ProviderConfig>` - A Box containing a KnoxConfig that has all further required parameters:
    ///   * key_algorithm: Option\<AsymmetricEncryption>,
    ///   * sym_algorithm: Option\<BlockCiphers>,
    ///   * env: JNIEnv<'a>
    ///
    ///   There must be exactly one of either key_algorithm or sym_algorithm provided.
    ///   If both are Some or None, the method returns an Error.
    ///   The env parameter is necessary to access the Java Virtual Machine from Rust code. When
    ///   calling Rust code from Java using the Java Native Interface, this value will be provided to the
    ///   Rust code by the JNI.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument(skip(config))]
    fn create_key(&mut self, key_id: &str, config: Box<dyn Any>) -> Result<(), SecurityModuleError> {
        let config = Self::downcast_config(config)?;
        let sym_alg = config.sym_algorithm;
        let asym_alg = config.key_algorithm;

        //Stores the vm for future access
        self.set_config(config);

        let key_algo;
        if asym_alg.is_some() && sym_alg.is_none() {
            key_algo = match asym_alg.expect("Already checked") {
                AsymmetricEncryption::Rsa(bitslength) => {
                    match bitslength {
                        KeyBits::Bits512 => { String::from("RSA;512;SHA-256;PKCS1") }
                        KeyBits::Bits1024 => { String::from("RSA;1024;SHA-256;PKCS1") }
                        KeyBits::Bits2048 => { String::from("RSA;2048;SHA-256;PKCS1") }
                        KeyBits::Bits3072 => { String::from("RSA;3072;SHA-256;PKCS1") }
                        KeyBits::Bits4096 => { String::from("RSA;4096;SHA-256;PKCS1") }
                        KeyBits::Bits8192 => { String::from("RSA;8192;SHA-256;PKCS1") }
                        _ => {
                            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                format!("Unsupported asymmetric encryption algorithm: {:?}",
                                        asym_alg))));
                        }
                    }
                }
                AsymmetricEncryption::Ecc(scheme) => {
                    match scheme {
                        EccSchemeAlgorithm::EcDsa(curve) => {
                            match curve {
                                EccCurves::P256 => { String::from("EC;secp256r1;SHA-256") }
                                EccCurves::P384 => { String::from("EC;secp384r1;SHA-256") }
                                EccCurves::P521 => { String::from("EC;secp521r1;SHA-256") }
                                //    EccCurves::Curve25519 => { String::from("EC;X25519;SHA-256") } <- x25519 may ONLY be used for key agreement, not signing
                                _ => {
                                    return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                        format!("Unsupported asymmetric encryption algorithm: {:?}",
                                                asym_alg))));
                                }
                            }
                        }
                        _ => {
                            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                format!("Unsupported asymmetric encryption algorithm: {:?}",
                                        asym_alg))));
                        }
                    }
                }
            };
        } else if asym_alg.is_none() && sym_alg.is_some() {
            key_algo = match sym_alg.expect("Already checked") {
                BlockCiphers::Des => { String::from("DESede;168;CBC;PKCS7Padding") }

                BlockCiphers::Aes(block, bitslength) => {
                    let mut rv = String::from("AES;");
                    match bitslength {
                        KeyBits::Bits128 => { rv += "128;"; }
                        KeyBits::Bits192 => { rv += "192;"; }
                        KeyBits::Bits256 => { rv += "256;"; }
                        _ => {
                            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                format!("Unsupported symmetric encryption algorithm: {:?}", sym_alg))));
                        }
                    }
                    match block {
                        SymmetricMode::Gcm => { rv += "GCM;NoPadding" }
                        SymmetricMode::Cbc => { rv += "CBC;PKCS7Padding" }
                        SymmetricMode::Ctr => { rv += "CTR;NoPadding" }
                        _ => {
                            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                format!("Unsupported symmetric encryption algorithm: {:?}", sym_alg))));
                        }
                    }
                    rv
                }
                _ => {
                    return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                        format!("Unsupported symmetric encryption algorithm: {:?}", sym_alg))));
                }
            };
        } else {
            return Err(SecurityModuleError::CreationError(format!(
                "wrong parameters in KnoxConfig:
                Exactly one of either sym_algorithm or key_algorithm must be Some().\
                sym_algorithm: {:?}\
                key_algorithm: {:?}",
                sym_alg,
                asym_alg)));
        }
        RustDef::create_key(&self.get_env()?, String::from(key_id), key_algo)
    }

    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method attempts to load a persisted cryptographic key by its identifier from the TPM.
    /// If successful, it sets the key usages and returns a handle to the key for further
    /// cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `key_algorithm` - The asymmetric encryption algorithm used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm used with the key.
    /// * `hash` - An optional hash algorithm used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn load_key(&mut self, key_id: &str, config: Box<dyn Any>) -> Result<(), SecurityModuleError> {
        let config = Self::downcast_config(config)?;

        //Stores the vm for future access
        self.set_config(config);

        // Call the create_key method with the correct parameters
        RustDef::load_key(&self.get_env()?, key_id.to_string())
    }

    /// Initializes the TPM module and returns a handle for cryptographic operations.
    ///
    /// This method opens a storage provider using the Windows CNG API and wraps it in a
    /// `WindowsProviderHandle`. This handle is used for subsequent cryptographic operations
    /// with the TPM.
    ///
    /// # Parameters
    ///
    /// - `key_algorithm`: Specifies the asymmetric encryption algorithm to use. Supported algorithms include:
    ///     - `AsymmetricEncryption::Rsa`: RSA with key lengths specified by `KeyBits`.
    /// - `sym_algorithm`: An optional parameter specifying the block cipher algorithm to use. Supported algorithms include:
    ///     - `BlockCiphers::Aes`: AES with key lengths specified by `KeyBits` and modes like GCM, ECB, CBC, CTR.
    /// - `hash`: An optional parameter specifying the hash algorithm to use.
    /// - `key_usages`: A vector specifying the purposes for which the key can be used (e.g., encrypt, decrypt, sign, verify).
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.
    ///
    /// # Errors
    ///
    /// This function returns a `SecurityModuleError` in the following cases:
    /// - If an unsupported asymmetric encryption algorithm is specified.
    /// - If an unsupported symmetric encryption algorithm is specified.
    ///
    /// # Examples
    ///
    /// rust
    /// let result = module.initialize_module(
    ///     AsymmetricEncryption::Rsa(KeyBits::Bits2048),
    ///     Some(BlockCiphers::Aes(KeyBits::Bits256)),
    ///     Some(Hash::Sha256),
    ///     vec![KeyUsage::Encrypt, KeyUsage::Decrypt],
    /// );
    ///
    /// match result {
    ///     Ok(()) =&gt; println!("Module initialized successfully"),
    ///     Err(e) =&gt; println!("Failed to initialize module: {:?}", e),
    /// }
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        Ok(())
    }
}

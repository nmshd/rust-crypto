use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, EccSchemeAlgorithm},
            },
        },
        error::SecurityModuleError,
        traits::module_provider::Provider,
    },
};
use tracing::instrument;
use crate::common::crypto::algorithms::encryption::{BlockCiphers, EccCurves, SymmetricMode};
use crate::common::crypto::algorithms::KeyBits;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::tpm::android::knox::interface::RustDef;
use crate::tpm::android::knox::{KnoxConfig, KnoxProvider};
use crate::tpm::core::error::TpmError::UnsupportedOperation;



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
    #[instrument]
    fn create_key(&mut self, key_id: &str, config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        let config = match config.as_any().downcast_ref::<KnoxConfig>() {
            None => {
                return Err(SecurityModuleError::CreationError(
                    String::from("Wrong type used for ProviderConfig in create_key()")));
            }
            Some(conf) => { conf }
        };

        let key_algo;
        if config.key_algorithm.is_some() && config.sym_algorithm.is_none() {
            key_algo = match config.key_algorithm.expect("Already checked") {
                AsymmetricEncryption::Rsa(bitslength) => {
                    match bitslength {
                        KeyBits::Bits128 => { String::from("RSA;128;SHA-256;PKCS1") }
                        KeyBits::Bits192 => { String::from("RSA;192;SHA-256;PKCS1") }
                        KeyBits::Bits256 => { String::from("RSA;256;SHA-256;PKCS1") }
                        KeyBits::Bits512 => { String::from("RSA;512;SHA-256;PKCS1") }
                        KeyBits::Bits1024 => { String::from("RSA;1024;SHA-256;PKCS1") }
                        KeyBits::Bits2048 => { String::from("RSA;2048;SHA-256;PKCS1") }
                        KeyBits::Bits3072 => { String::from("RSA;3072;SHA-256;PKCS1") }
                        KeyBits::Bits4096 => { String::from("RSA;4096;SHA-256;PKCS1") }
                        KeyBits::Bits8192 => { String::from("RSA;8192;SHA-256;PKCS1") }
                    }
                }
                AsymmetricEncryption::Ecc(scheme) => { //todo: test in java prototype
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
                                                config.key_algorithm))));
                                }
                            }
                        }
                        _ => {return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                            format!("Unsupported asymmetric encryption algorithm: {:?}",
                                    config.key_algorithm))));
                        }
                    }
                }
            };
        } else if config.key_algorithm.is_none() && config.sym_algorithm.is_some() {
            key_algo = match config.sym_algorithm.expect("Already checked") {
                BlockCiphers::Des => { String::from("DESede;CBC;PKCS7Padding") },

                BlockCiphers::Aes(block, bitslength) => {
                    let mut rv = String::from("AES;");
                    match bitslength {
                        KeyBits::Bits128 => { rv += "128;"; }
                        KeyBits::Bits192 => { rv += "192;"; }
                        KeyBits::Bits256 => { rv += "256;"; }
                        _ => {
                            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                format!("Unsupported symmetric encryption algorithm: {:?}", config.sym_algorithm))));
                        }
                    }
                    match block { //todo: check if paddings match blocking modes
                        SymmetricMode::Gcm => { rv += "GCM;NoPadding" }
                        SymmetricMode::Cbc => { rv += "CBC;PKCS7Padding" }
                        SymmetricMode::Ctr => { rv += "CTR;NoPadding" }
                        _ => {
                            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                                format!("Unsupported symmetric encryption algorithm: {:?}", config.sym_algorithm))));
                        }
                    }
                    rv
                },
                _ => {
                    return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                        format!("Unsupported symmetric encryption algorithm: {:?}", config.sym_algorithm))));
                }
            };
        } else {
            return Err(SecurityModuleError::CreationError(format!(
                "wrong parameters in KnoxConfig:
                Exactly one of either sym_algorithm or key_algorithm must be Some().\
                sym_algorithm: {:?}\
                key_algorithm: {:?}",
                config.sym_algorithm,
                config.key_algorithm)));
        }
        RustDef::create_key(config.vm, String::from(key_id), key_algo)
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
    fn load_key(&mut self, key_id: &str, config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        let config = match config.as_any().downcast_ref::<KnoxConfig>() {
            None => {
                return Err(SecurityModuleError::CreationError(
                    String::from("Wrong type used for ProviderConfig in create_key()")));
            }
            Some(conf) => { conf }
        };

        let env = match Self::jvm_to_jnienv(&config) {
            Ok(value) => value,
            Err(value) => return value,
        };
        RustDef::load_key(&env, String::from(key_id))
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
    /// ```rust
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

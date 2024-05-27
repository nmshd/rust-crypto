use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, BlockCiphers, EccSchemeAlgorithm},
                hashes::Hash,
            },
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::module_provider::Provider,
    },
};
use tracing::instrument;
use serde::de::Unexpected::Option;
use crate::common::crypto::algorithms::encryption::EccCurves;
use crate::common::crypto::algorithms::hashes::{Sha2Bits, Sha3Bits};
use crate::common::crypto::algorithms::KeyBits;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::tpm::android::knox::interface::jni::RustDef;
use crate::tpm::core::error::TpmError::UnsupportedOperation;
use crate::tpm::linux::TpmProvider;
use crate::tpm::TpmConfig;


/// Implements the `Provider` trait, providing cryptographic operations utilizing a TPM.
///
/// This implementation is specific to the Windows platform and utilizes the Windows CNG API
/// to interact with the Trusted Platform Module (TPM) for key management and cryptographic
/// operations.
impl Provider for TpmProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    /// with the specified key usages and stored in the TPM.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm to be used with the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn create_key(&mut self, key_id: &str, config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        let config = config.as_any().downcast_ref::<TpmConfig>().unwrap();

        //Knox Vault only supports SHA256
        if !config.hash == Hash::Sha2(Sha2Bits::Sha256) {
            return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                format!("Unsupported hashing algorithm: {:?}", config.hash))));
        }

        let asym_string = match config.key_algorithm {
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
            AsymmetricEncryption::Ecc(scheme) => { //todo
                match scheme {
                    EccSchemeAlgorithm::EcDsa(curve) => {
                        match curve {
                            EccCurves::P256 => {}
                            EccCurves::P384 => {}
                            EccCurves::P521 => {}
                            EccCurves::Secp256k1 => {}
                            EccCurves::BrainpoolP256r1 => {}
                            EccCurves::BrainpoolP384r1 => {}
                            EccCurves::BrainpoolP512r1 => {}
                            EccCurves::BrainpoolP638 => {}
                            EccCurves::Curve25519 => {}
                            EccCurves::Curve448 => {}
                            EccCurves::Frp256v1 => {}
                        }
                    }

                    _ => {}
                }
            }
            _ => {
                return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                    format!("Unsupported asymmetric encryption algorithm: {:?}",
                            config.key_algorithm))));
            }
        };

        let sym_string = match config.sym_algorithm {
            Option::DESede(bitslength) => {
                match bitslength {
                    KeyBits::Bits128 => { String::from("DESede;CBC;PKCS7,PKCS5Padding") } //todo which one?
                    KeyBits::Bits128 => { String::from("DESede;ECB;PKCS7,NoPadding") }
                }
            },
            Option::Aes(bitslength) => {
                match bitslength {
                    KeyBits::Bits128 => { String::from("AES;128;GCM;NoPadding") }
                    KeyBits::Bits192 => { String::from("AES;192;GCM;NoPadding") }
                    KeyBits::Bits256 => { String::from("AES;256;GCM;NoPadding") }
                }
            },
            _ => {
                return Err(SecurityModuleError::Tpm(UnsupportedOperation(
                    format!("Unsupported symmetric encryption algorithm: {:?}", config.sym_algorithm))));
            }
        };

        RustDef::create_key(&(), key_id, format!("{};{};"))
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
    fn load_key(&mut self, key_id: &str, _config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        Ok(())
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

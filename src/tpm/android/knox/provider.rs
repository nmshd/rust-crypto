use std::any::Any;

use tracing::instrument;

use crate::{
    common::{
        crypto::algorithms::{
            encryption::{
                AsymmetricEncryption,
                BlockCiphers,
                EccCurves,
                EccSchemeAlgorithm,
                SymmetricMode,
            },
            KeyBits
        },
        error::SecurityModuleError,
        traits::module_provider::Provider,
    },
    tpm::{
        android::knox::{
            interface::jni::RustDef,
            KnoxProvider
        },
        core::error::TpmError::UnsupportedOperation
    }
};

/// Implements the `Provider` trait, providing cryptographic operations utilizing a TPM.
///
/// This implementation is specific to Samsung Knox Vault and uses the Android Keystore API for all cryptographic operations
/// In theory, this should also work for other TPMs on Android phones, but it is only tested with Samsung Knox Vault
impl Provider for KnoxProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    /// and stored in Knox Vault. This method also loads the key for further usage, therefore it is
    /// not necessary to load a key after creating it.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `Box<dyn Any`- This box must contain a KnoxConfig, otherwise an Error is returned.
    ///    A KnoxConfig must contain the algorithm to be used as well as a reference to the JavaVM of the app
    ///    More details can be found in its [documentation](crate::tpm::android::knox::KnoxConfig)
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created and stored successfully.
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
                BlockCiphers::Des => { String::from("DESede;CBC;PKCS7Padding") }

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
    /// If successful, it enables the key to be used for cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `Box<dyn Any`- This box must contain a KnoxConfig, otherwise an Error is returned.
    ///    A KnoxConfig must contain the algorithm to be used as well as a reference to the JavaVM of the app
    ///    More details can be found in its [documentation](crate::tpm::android::knox::KnoxConfig)
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn load_key(&mut self, key_id: &str, config: Box<dyn Any>) -> Result<(), SecurityModuleError> {
        //Stores the vm for future access
        let config = Self::downcast_config(config)?;
        self.set_config(config);

        RustDef::load_key(&self.get_env()?, key_id.to_string())
    }

    ///This function ordinarily initialises the HSM.
    /// For our implementation, this is not needed. You do not need to call this method,
    /// and it will always return Ok(()) if you do.
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        Ok(())
    }
}

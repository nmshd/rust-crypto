use super::{SecureEnclaveConfig, SecureEnclaveProvider};
extern crate apple_secure_enclave_bindings;
use crate::
    common::{
        crypto::algorithms::{encryption::{AsymmetricEncryption, EccCurves, EccSchemeAlgorithm}, hashes::Hash, KeyBits},
        error::SecurityModuleError,
        traits::module_provider::Provider,
    };
use regex::Regex;
use crate::common::crypto::algorithms::hashes::*; 
use std::any::Any;
use crate::common::error::SecurityModuleError::InitializationError; 
use tracing::instrument;


/// Implements the `Provider` trait, providing cryptographic operations utilizing a Secure Enclave.
impl Provider for SecureEnclaveProvider {

    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    /// with the specified key usages and stored in the Secure Enclave.
    /// 
    /// Uses the rust_crypto_call_create_key function from the Swift Secure Enclave bindings.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `config` - A boxed `SecureEnclaveConfig` object containing the configuration for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn create_key(
        &mut self,
        _key_id: &str,
        _config: Box<dyn Any>,
    ) -> Result<(), SecurityModuleError> {
        let config = *_config.downcast::<SecureEnclaveConfig>().map_err(|_| SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?; 
        let key_algorithm_type;

        if config.asym_algorithm.is_some(){
            key_algorithm_type = match config.asym_algorithm.expect("No Asymmetric Algorithm given.") {
                AsymmetricEncryption::Rsa(keybits) => {
                    match keybits {
                        //Works only in combination with SHA1, SHA224
                        KeyBits::Bits512 => "RSA;512".to_string(),
                        //Works only in combination with SHA256, SHA384
                        KeyBits::Bits1024 => "RSA;1024".to_string(),
                        _ => unimplemented!("With RSA only Keysize of 512 and 1024 are supported"),
                    }
                }
                AsymmetricEncryption::Ecc(ecc_scheme_algo) => {
                    match ecc_scheme_algo {
                        EccSchemeAlgorithm::EcDsa(ecc_curve) => {
                            match ecc_curve{
                                EccCurves::P256 => "ECDSA;256".to_string(),
                                EccCurves::P384 => "ECDSA;384".to_string(),
                                // EccCurves::P521 => "ECDSA;521".to_string(), Not supported by Secure Enclave
                                _ => {return Err(InitializationError("Ecc-Curve is not supported. Only P256 and P384 are supported.".to_string()))}
                            }
                        }
                        _ => {return Err(InitializationError("Algorithm is not supported".to_string()))} 
                    }
                }
            };

            let keypair = apple_secure_enclave_bindings::provider::rust_crypto_call_create_key(self.key_id.clone(), key_algorithm_type);

            if Regex::new("(?i)error").unwrap().is_match(keypair.as_str()) {
                Err(SecurityModuleError::InitializationError(keypair.to_string()))
            } else {
                Ok(())
            }
        }else{
            return Err(InitializationError("Algorithm is not supported".to_string()))
        }
        
    }

    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method attempts to load a persisted cryptographic key by its identifier from the Secure Enclave.
    /// If successful, it sets the key usages and returns a handle to the key for further
    /// cryptographic operations.
    /// 
    /// Uses the rust_crypto_call_load_key function from the Swift Secure Enclave bindings.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `key_algorithm` - The asymmetric encryption algorithm used for the key.
    /// * `config` - A boxed `SecureEnclaveConfig` object containing the configuration for the key.
    /// 
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn load_key(
        &mut self,
        _key_id: &str,
        _config: Box<dyn Any>,
    ) -> Result<(), SecurityModuleError> {
        let config = *_config.downcast::<SecureEnclaveConfig>().map_err(|_| SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?; 
        let _ = self.set_config(config.clone());
        let algorithm = convert_algorithms(config.clone()); 
        let hash = convert_hash(config.hash.expect("No Hash given"));

        let load_key = apple_secure_enclave_bindings::provider::rust_crypto_call_load_key(_key_id.to_string(), algorithm, hash);

        if Regex::new("(?i)error").unwrap().is_match(load_key.as_str()){
            Err(SecurityModuleError::InitializationError(load_key.to_string()))
        } else {
            Ok(())
        }
    }


    /// Initializes the Secure Enclave module and returns a handle for cryptographic operations.
    ///
    /// This method initializes the Secure Enclave context and prepares it for use. It should be called
    /// before performing any other operations with the Secure Enclave.
    /// 
    /// Uses the rust_crypto_call_sign_data function from the Swift Secure Enclave bindings.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        let initialization_result =
            apple_secure_enclave_bindings::provider::rust_crypto_call_initialize_module();

        match initialization_result {
            true => Ok(()),
            false => Err(SecurityModuleError::InitializationError(
                "Failed to initialize module".to_string(),
            )),
        }
    }
}

/// Converts the algorithm type to a String.
/// 
/// # Arguments
/// 
/// * `config` - A `SecureEnclaveConfig` object containing the configuration for the key.
/// 
/// # Returns
/// 
/// A `String` containing the AsymmetricEncryption algorithm.
pub fn convert_algorithms(config: SecureEnclaveConfig) -> String {
    let asym_algorithm_type = match config.asym_algorithm.expect("Invalid config") {
        // Is only Asymmetric-Algorithm which is working at that time
        AsymmetricEncryption::Rsa(_) => "RSA".to_string(),
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(_)) => "ECDSA".to_string(), 
        _ => unimplemented!("Only RSA and ECDSA supported") ,
    };

    asym_algorithm_type
}


/// Converts the Hash algorithm to a String.
/// 
/// # Arguments
/// 
/// * `hash` - A `Hash` object containing the hash algorithm.
/// 
/// # Returns
/// 
/// A `String` containing the Hash algorithm.
pub fn convert_hash(hash: Hash) -> String {
    match hash {
        Hash::Sha2(sha2_bits) =>{
            match sha2_bits {
                Sha2Bits::Sha224 => "SHA224".to_string(),
                Sha2Bits::Sha256 => "SHA256".to_string(),
                Sha2Bits::Sha384 => "SHA384".to_string(),
                Sha2Bits::Sha512 => "SHA512".to_string(),
                _ => unimplemented!("Only SHA224, SHA256, SHA384, SHA512 supported."),            
            }
        }, 
        _ => unimplemented!("Only SHA1 and Sha2Bits supported."), 
    }
}

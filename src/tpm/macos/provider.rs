use super::{SecureEnclaveConfig, SecureEnclaveProvider};
extern crate apple_secure_enclave_bindings;
use crate::
    common::{
        crypto::algorithms::{encryption::AsymmetricEncryption, hashes::Hash, KeyBits},
        error::SecurityModuleError,
        traits::module_provider::Provider,
    };
use regex::Regex;
use crate::common::crypto::algorithms::hashes::*; 
use std::any::Any;
use crate::common::error::SecurityModuleError::CreateKeyError; 
use tracing::instrument;


impl Provider for SecureEnclaveProvider {
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
                _ => unimplemented!("Only RSA supported"),
            };

            // Debug TODO
            println!("Algorithm {}", key_algorithm_type); 

            let keypair = apple_secure_enclave_bindings::provider::rust_crypto_call_create_key(self.key_id.clone(), key_algorithm_type);

            if Regex::new("(?i)error").unwrap().is_match(keypair.as_str()) {
                Err(SecurityModuleError::CreateKeyError(keypair.to_string()))
            } else {
                //Debug TODO
                println!("\nGenerated KeyPair:\n{}", keypair);
                Ok(())
            }
        }else{
            return Err(CreateKeyError("Algorithm is not supported".to_string()))
        }
        
    }

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

pub fn convert_algorithms(config: SecureEnclaveConfig) -> String {
    let asym_algorithm_type = match config.asym_algorithm.expect("Invalid config") {
        // Is only Asymmetric-Algorithm which is working at that time
        AsymmetricEncryption::Rsa(_) => "RSA".to_string(), 
        _ => unimplemented!("Only RSA supported") ,
    };
    //Debug TODO
    println!("Converted Algo: {}", asym_algorithm_type); 

    asym_algorithm_type
}

pub fn convert_hash(hash: Hash) -> String {
    match hash {
        Hash::Sha1 => "SHA1".to_string(),
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




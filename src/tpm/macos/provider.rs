use super::{SecureEnclaveConfig, SecureEnclaveProvider};
extern crate apple_secure_enclave_bindings;
use crate::
    common::{
        crypto::algorithms::{encryption::{AsymmetricEncryption, EccCurves, EccSchemeAlgorithm}, hashes::Hash},
        error::SecurityModuleError,
        traits::module_provider::Provider,
    }
;
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

        if config.key_algorithm.is_some(){
            key_algorithm_type = match config.key_algorithm.expect("No Algorithm for Key-Generation is not given") {
                // Is only Algorithm which is working at that time
                AsymmetricEncryption::Ecc(ecc_scheme_algo) => {
                    match ecc_scheme_algo {
                        EccSchemeAlgorithm::EcDsa(ecc_curve) => {
                            match ecc_curve{
                                // P256,P384,P521 are deprecated please use Secp256k1 instead
                                EccCurves::P256 => "kSecAttrKeyTypeECDSA;256".to_string(),
                                EccCurves::P384 => "kSecAttrKeyTypeECDSA;384".to_string(),
                                // EccCurves::P521 => "kSecAttrKeyTypeECDSA;521".to_string(), // Not supported by Secure Enclave
                                EccCurves::Secp256k1 => "kSecAttrKeyTypeECSECPrimeRandom;256".to_string(), 
                                _ => {return Err(CreateKeyError("Algorithm is not supported".to_string()))}
                            }
                        }
                        _ => {return Err(CreateKeyError("Algorithm is not supported".to_string()))} 
                    }
                }
                _ => {return Err(CreateKeyError("Algorithm is not supported".to_string()))} 
            };

            // Debug TODO
            // println!("Algorithm {}", key_algorithm_type); 

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
        
        let _ = self.set_config(config);

        let load_key = apple_secure_enclave_bindings::provider::rust_crypto_call_load_key(_key_id.to_string());

        if Regex::new("(?i)error")
            .unwrap()
            .is_match(load_key.as_str())
        {
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


pub fn convert_key_gen_algorithms() -> String {
    todo!()
}

pub fn convert_encrypt_algorithms() -> String {
    todo!()
}

pub fn convert_sign_algorithms(config: SecureEnclaveConfig) -> String {
    let algo; 

    let key_algorithm_type = match config.asym_algorithm.expect("Hello") {
        // Is only Algorithm which is working at that time
        AsymmetricEncryption::Ecc(ecc_scheme_algo) => {
            match ecc_scheme_algo {
                EccSchemeAlgorithm::Null => {
                    "ecc".to_string()
                }
                _ => unimplemented!()
            }
        }
        _ => unimplemented!()
    };
    let hash = convert_hash(config.hash.expect("No Hash given")); 
    
    algo = key_algorithm_type + ";" + &hash;  

    return algo
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
                _ => unimplemented!(),            
            }
        }, 
        _ => unimplemented!(), 
    }
}




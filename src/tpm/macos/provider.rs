use super::{SecureEnclaveConfig, TpmProvider};
extern crate apple_secure_enclave_bindings;
use crate::
    common::{
        crypto::{
            algorithms::{encryption::{AsymmetricEncryption, EccCurves, EccSchemeAlgorithm}, KeyBits},
            KeyUsage,
         },
        error::SecurityModuleError,
        traits::{module_provider::Provider, module_provider_config::ProviderConfig},
    }
;
use regex::Regex;

use std::any::Any;
use crate::common::error::SecurityModuleError::CreateKeyError; 

// use tracing::instrument;

impl Provider for TpmProvider {
    
    // #[instrument]
    fn create_key(
        &mut self,
        _key_id: &str,
        _config: Box<dyn Any>,
    ) -> Result<(), SecurityModuleError> {
        let config = *_config.downcast::<SecureEnclaveConfig>().map_err(|_| SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?; 

        if config.sym_alogorithm.is_none() && config.key_algorithm.is_some(){
            let key_algorithm_type = match config.key_algorithm.expect("Hello") {
                AsymmetricEncryption::Rsa(key_bits) => {
                    match key_bits{
                        KeyBits::Bits1024 => todo!(),
                        KeyBits::Bits128 => todo!(),
                        KeyBits::Bits192 => todo!(),
                        KeyBits::Bits256 => "kSecAttrKeyTypeRSA;256".to_string(),
                        KeyBits::Bits512 => todo!(),
                        KeyBits::Bits2048 => todo!(),
                        KeyBits::Bits3072 => todo!(),
                        KeyBits::Bits4096 => todo!(),
                        KeyBits::Bits8192 => todo!(),

                    }
                }
                // Is only Algorithm which is working at that time
                AsymmetricEncryption::Ecc(ecc_scheme_algo) => {
                    match ecc_scheme_algo {
                        EccSchemeAlgorithm::EcDsa(ecc_curve) => {
                            match ecc_curve{
                                EccCurves::P256 => "kSecAttrKeyTypeECDSA;256".to_string(),
                                _ => {return Err(CreateKeyError("Algorithm is not supported".to_string()))}
                            }
                        }
                        _ => {return Err(CreateKeyError("Algorithm is not supported".to_string()))} 
                    }
                }
            }; 
            println!("Algorithm {}", key_algorithm_type); 
            let keypair = apple_secure_enclave_bindings::provider::rust_crypto_call_create_key(self.key_id.clone(), key_algorithm_type);
            
            if Regex::new("(?i)error").unwrap().is_match(keypair.as_str()) {
                Err(SecurityModuleError::CreateKeyError(keypair.to_string()))
            } else {
                println!("Generated KeyPair:{}", keypair);
                Ok(())
            }
        }else{
            if Regex::new("(?i)error").unwrap().is_match("keypair") {
                Err(SecurityModuleError::CreateKeyError("keypair".to_string()))
            } else {
                println!("Not generated KeyPair:");
                Ok(())
            }
        }


        
    }

    // #[instrument]
    fn load_key(
        &mut self,
        _key_id: &str,
        _config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        //wie die anderen Teams es gemacht haben mit config und in module_privider_config.rs:
        //let config = match config.as_any().downcast_ref::<Config>()
        let private_key = apple_secure_enclave_bindings::provider::rust_crypto_call_load_key();

        //welcher Error?
        if Regex::new("(?i)error")
            .unwrap()
            .is_match(private_key.as_str())
        {
            Err(SecurityModuleError::LoadKeyError(private_key.to_string()))
        } else {
            Ok(())
        }
    }

    // #[instrument]
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




use super::TpmProvider;
extern crate apple_secure_enclave_bindings;
use crate::
    common::{
        crypto::{
            algorithms::encryption::{AsymmetricEncryption, EccSchemeAlgorithm},
            KeyUsage,
         },
        error::SecurityModuleError,
        traits::{module_provider::Provider, module_provider_config::ProviderConfig},
    }
;
use regex::Regex;

// use tracing::instrument;

impl Provider for TpmProvider {
    
    // #[instrument]
    fn create_key(
        &mut self,
        _key_id: &str,
        _config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        //wie die anderen Teams es gemacht haben mit config und in module_privider_config.rs:
        //let config = match config.as_any().downcast_ref::<Config>()

        //welcher Error?
        //let string_key_id = String::from_utf8(key_id.map_err(|_| SecurityModuleError::Error("Key ID conversion error".to_string())))?;
        let keypair = apple_secure_enclave_bindings::provider::rust_crypto_call_create_key();

        if Regex::new("(?i)error").unwrap().is_match(keypair.as_str()) {
            Err(SecurityModuleError::CreateKeyError(keypair.to_string()))
        } else {
            Ok(())
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

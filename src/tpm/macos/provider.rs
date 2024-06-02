use super::TpmProvider;
extern crate apple_secure_enclave_bindings;
use crate::{
    common::{
        crypto::{
            algorithms::encryption::{AsymmetricEncryption, EccSchemeAlgorithm},
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::{module_provider::Provider, module_provider_config::ProviderConfig},
    },
    tpm::{core::error::TpmError, TpmConfig},
};
use regex::Regex;

use tracing::instrument;

impl Provider for TpmProvider {
    
    // #[instrument]
    fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        let config = config.as_any().downcast_ref::<SEConfig>().unwrap();

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
        key_id: &str,
        config: Box<dyn ProviderConfig>,
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

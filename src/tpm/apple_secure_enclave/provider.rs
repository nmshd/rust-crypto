use std::collections::HashSet;

use async_trait::async_trait;
use security_framework::key::SecKey;

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    error::SecurityModuleError,
    traits::module_provider::{ProviderFactory, ProviderImpl},
};

struct AppleSecureEnclaveFactory {}

#[async_trait]
impl ProviderFactory for AppleSecureEnclaveFactory {
    fn get_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }

    async fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig {
        match impl_config {
            ProviderImplConfig::AppleSecureEnclave {} => {}
            _ => panic!("Invalid ProviderImplConfig supplied."),
        }

        ProviderConfig {
            max_security_level: SecurityLevel::Hardware,
            min_security_level: SecurityLevel::Hardware,
            supported_ciphers: HashSet::new(),
            supported_asym_spec: HashSet::from([]),
            supported_hashes: HashSet::from([]),
        }
    }

    async fn create_provider(&self, impl_config: ProviderImplConfig) -> Box<dyn ProviderImpl> {
        Box::new(AppleSecureEnclaveProvider {})
    }
}

#[derive(Debug)]
struct AppleSecureEnclaveProvider {}

#[async_trait]
impl ProviderImpl for AppleSecureEnclaveProvider {
    async fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn load_key(&mut self, key_id: String) -> Result<KeyHandle, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn load_key_pair(
        &mut self,
        key_id: String,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn import_key(
        &mut self,
        spec: KeySpec,
        data: &[u8],
    ) -> Result<KeyHandle, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<DHExchange, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    fn provider_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }
}

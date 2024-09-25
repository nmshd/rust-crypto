use async_trait::async_trait;

use crate::common::{
    config::{AlgorithmMetadata, DHSpec, KeyPairSpec, KeySpec, ProviderConfig},
    error::SecurityModuleError,
    traits::{
        key_handle::{DHKeyExchange, KeyHandle, KeyPairHandle},
        module_provider::{Provider, ProviderFactory},
    },
};

pub struct StubProviderFactory;

#[async_trait]
impl ProviderFactory for StubProviderFactory {
    fn get_name(&self) -> String {
        return "StubProvider".to_owned();
    }

    async fn get_capabilities(&mut self) -> AlgorithmMetadata {
        return AlgorithmMetadata;
    }

    async fn check_config(&mut self, config: &ProviderConfig) -> bool {
        return true;
    }

    async fn create_provider(self, config: ProviderConfig) -> Box<dyn Provider> {
        return Box::new(StubProvider);
    }
}

pub struct StubProvider;

#[async_trait]
impl Provider for StubProvider {
    async fn create_key(
        &mut self,
        spec: KeySpec,
    ) -> Result<Box<dyn KeyHandle>, SecurityModuleError> {
        todo!()
    }

    async fn load_key(&mut self, id: &str) -> Result<Box<dyn KeyHandle>, SecurityModuleError> {
        todo!()
    }

    async fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<Box<dyn KeyPairHandle>, SecurityModuleError> {
        todo!()
    }

    async fn load_key_pair(
        &mut self,
        id: &str,
    ) -> Result<Box<dyn KeyPairHandle>, SecurityModuleError> {
        todo!()
    }

    async fn start_dh_exchange(
        &mut self,
        spec: DHSpec,
    ) -> Result<Box<dyn DHKeyExchange>, SecurityModuleError> {
        todo!()
    }
}

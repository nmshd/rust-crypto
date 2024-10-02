use async_trait::async_trait;

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig},
    error::SecurityModuleError,
    traits::module_provider::{ProviderFactory, ProviderImpl},
    DHExchange, KeyHandle, KeyPairHandle,
};

const PROVIDER_NAME: &'static str = "STUB_PROVIDER";

pub struct StubProviderFactory {}

#[async_trait]
impl ProviderFactory for StubProviderFactory {
    fn get_name(&self) -> String {
        return PROVIDER_NAME.to_owned();
    }

    async fn get_capabilities(&mut self, impl_config: ProviderImplConfig) -> ProviderConfig {
        todo!()
    }

    async fn create_provider(self, impl_config: ProviderImplConfig) -> Box<dyn ProviderImpl> {
        return Box::new(StubProvider {});
    }
}

pub struct StubProvider {}

#[async_trait]
impl ProviderImpl for StubProvider {
    async fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError> {
        todo!()
    }

    async fn load_key(&mut self, id: String) -> Result<KeyHandle, SecurityModuleError> {
        todo!()
    }

    async fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn load_key_pair(&mut self, id: String) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn import_key(
        &mut self,
        spec: KeySpec,
        data: &[u8],
    ) -> Result<KeyHandle, SecurityModuleError> {
        todo!()
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
        todo!()
    }

    fn provider_name(&self) -> String {
        PROVIDER_NAME.to_owned()
    }
}

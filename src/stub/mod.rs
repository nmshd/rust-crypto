#![allow(unused)]
#![allow(dead_code)]

use std::{collections::HashSet, hash::Hash};

use async_trait::async_trait;
use flutter_rust_bridge::frb;

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    error::SecurityModuleError,
    traits::{
        key_handle::KeyPairHandleImpl,
        module_provider::{ProviderFactory, ProviderImpl},
    },
    DHExchange, KeyHandle, KeyPairHandle,
};

const PROVIDER_NAME: &str = "STUB_PROVIDER";

#[cfg_attr(feature = "flutter", frb(opaque))]
pub struct StubProviderFactory {}

#[async_trait]
impl ProviderFactory for StubProviderFactory {
    fn get_name(&self) -> String {
        return PROVIDER_NAME.to_owned();
    }

    async fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig {
        return ProviderConfig {
            min_security_level: SecurityLevel::Software,
            max_security_level: SecurityLevel::Software,
            supported_asym_spec: HashSet::new(),
            supported_ciphers: HashSet::new(),
            supported_hashes: HashSet::new(),
        };
    }

    async fn create_provider(&self, impl_config: ProviderImplConfig) -> Box<dyn ProviderImpl> {
        return Box::new(StubProvider {});
    }
}

#[cfg_attr(feature = "flutter", frb(opaque))]
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
        Ok(KeyPairHandle {
            implementation: Box::new(StubKeyPairHandle {}),
        })
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

#[cfg_attr(feature = "flutter", frb(opaque))]
struct StubKeyPairHandle {}

#[async_trait]
impl KeyPairHandleImpl for StubKeyPairHandle {
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Ok(data.to_vec())
    }

    async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        return Ok(data == signature);
    }

    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    async fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    async fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    async fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, SecurityModuleError> {
        todo!()
    }
}

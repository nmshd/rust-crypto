#![allow(unused)]
#![allow(dead_code)]

use std::{collections::HashSet, hash::Hash};

use async_trait::async_trait;
use flutter_rust_bridge::frb;

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    error::SecurityModuleError,
    traits::module_provider::ProviderImplEnum,
    DHExchange, KeyHandle, KeyPairHandle,
};

const PROVIDER_NAME: &str = "STUB_PROVIDER";

#[cfg_attr(feature = "flutter", frb(opaque))]
pub(crate) struct StubProviderFactory {}

impl StubProviderFactory {
    pub(crate) fn get_name(&self) -> String {
        return PROVIDER_NAME.to_owned();
    }

    pub(crate) fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig {
        return ProviderConfig {
            min_security_level: SecurityLevel::Software,
            max_security_level: SecurityLevel::Software,
            supported_asym_spec: HashSet::new(),
            supported_ciphers: HashSet::new(),
            supported_hashes: HashSet::new(),
        };
    }

    pub(crate) fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        return (StubProvider {}).into();
    }
}

#[frb(opaque)]
pub(crate) struct StubProvider {}

impl StubProvider {
    pub(crate) fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn load_key(&mut self, id: String) -> Result<KeyHandle, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        Ok(KeyPairHandle {
            implementation: (StubKeyPairHandle {}).into(),
        })
    }

    pub(crate) fn load_key_pair(
        &mut self,
        id: String,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn import_key(
        &mut self,
        spec: KeySpec,
        data: &[u8],
    ) -> Result<KeyHandle, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<DHExchange, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn provider_name(&self) -> String {
        PROVIDER_NAME.to_owned()
    }
}

#[cfg_attr(feature = "flutter", frb(opaque))]
pub(crate) struct StubKeyPairHandle {}

impl StubKeyPairHandle {
    pub(crate) fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Ok(data.to_vec())
    }

    pub(crate) fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        return Ok(data == signature);
    }

    pub(crate) fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn decrypt_data(
        &self,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn start_dh_exchange(&self) -> Result<DHExchange, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn id(&self) -> Result<String, SecurityModuleError> {
        Ok("RANDOM_KEY_ID".to_owned())
    }
}

pub(crate) struct StubKeyHandle {}

impl StubKeyHandle {
    pub(crate) fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn decrypt_data(
        &self,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    pub(crate) fn id(&self) -> Result<String, SecurityModuleError> {
        Ok("RANDOM_KEY_ID".to_owned())
    }
}

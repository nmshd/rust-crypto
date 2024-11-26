#![allow(unused)]
#![allow(dead_code)]

use std::{collections::HashSet, hash::Hash};

use serde_json::error;

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    error::CalError,
    traits::{
        key_handle::{DHKeyExchangeImpl, KeyHandleImpl, KeyPairHandleImpl},
        module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
    },
    DHExchange, KeyHandle, KeyPairHandle,
};

const PROVIDER_NAME: &str = "STUB_PROVIDER";

pub(crate) struct StubProviderFactory {}

impl ProviderFactory for StubProviderFactory {
    fn get_name(&self) -> String {
        PROVIDER_NAME.to_owned()
    }

    fn get_capabilities(&self, impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        Some(ProviderConfig {
            min_security_level: SecurityLevel::Software,
            max_security_level: SecurityLevel::Software,
            supported_asym_spec: HashSet::new(),
            supported_ciphers: HashSet::new(),
            supported_hashes: HashSet::new(),
        })
    }

    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        (StubProvider { impl_config }).into()
    }
}

pub(crate) struct StubProvider {
    impl_config: ProviderImplConfig,
}

impl ProviderImpl for StubProvider {
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn load_key(&mut self, id: String) -> Result<KeyHandle, CalError> {
        todo!()
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        Ok(KeyPairHandle {
            implementation: (StubKeyPairHandle {}).into(),
        })
    }

    fn load_key_pair(&mut self, id: String) -> Result<KeyPairHandle, CalError> {
        todo!()
    }

    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        todo!()
    }

    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        todo!()
    }

    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        todo!()
    }

    fn start_ephemeral_dh_exchange(&mut self, spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        todo!()
    }

    fn provider_name(&self) -> String {
        PROVIDER_NAME.to_owned()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        StubProviderFactory {}.get_capabilities(self.impl_config.clone())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StubKeyPairHandle {}

impl KeyPairHandleImpl for StubKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        Ok(data.to_vec())
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        Ok(data == signature)
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        todo!()
    }

    fn id(&self) -> Result<String, CalError> {
        Ok("RANDOM_KEY_ID".to_owned())
    }

    fn delete(self) -> Result<(), CalError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StubKeyHandle {}

impl KeyHandleImpl for StubKeyHandle {
    fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        todo!()
    }

    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn id(&self) -> Result<String, CalError> {
        Ok("RANDOM_KEY_ID".to_owned())
    }

    fn delete(self) -> Result<(), CalError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StubDHKeyExchange;

impl DHKeyExchangeImpl for StubDHKeyExchange {
    /// Get the public key of the internal key pair to use for the other party
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    /// add an external public point and compute the shared secret. The raw secret is returned to use in another round of the key exchange
    fn add_external(&mut self, external_key: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    /// add the final external Keypair, derive a symmetric key from the shared secret and store the key
    fn add_external_final(&mut self, external_key: &[u8]) -> Result<KeyHandle, CalError> {
        todo!()
    }
}

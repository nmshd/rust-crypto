#![allow(unused)]
#![allow(dead_code)]

use std::{collections::HashSet, hash::Hash};

use serde_json::error;

use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel, Spec},
        error::CalError,
        traits::{
            key_handle::{DHKeyExchangeImpl, KeyHandleImpl, KeyPairHandleImpl},
            module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
        },
        DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::KDF,
    storage::KeyData,
};

const PROVIDER_NAME: &str = "STUB_PROVIDER";

pub(crate) struct StubProviderFactory {}

impl ProviderFactory for StubProviderFactory {
    fn get_name(&self) -> Option<String> {
        Some(PROVIDER_NAME.to_owned())
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

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        Ok((StubProvider { impl_config }).into())
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

    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        todo!()
    }

    fn provider_name(&self) -> String {
        PROVIDER_NAME.to_owned()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        StubProviderFactory {}.get_capabilities(self.impl_config.clone())
    }

    #[doc = " Derives a high-entropy key from a low-entropy password and a unique salt"]
    fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        algorithm: KeySpec,
        kdf: KDF,
    ) -> Result<KeyHandle, CalError> {
        todo!()
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

    fn spec(&self) -> KeyPairSpec {
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

    fn hmac(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn verify_hmac(&self, data: &[u8], hmac: &[u8]) -> Result<bool, CalError> {
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

    fn spec(&self) -> KeySpec {
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

    #[doc = " Derive client session keys (rx, tx) - client is the templator in your code"]
    fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        todo!()
    }

    #[doc = " Derive server session keys (rx, tx) - server is the requestor in your code"]
    fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        todo!()
    }

    fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        todo!()
    }

    fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        todo!()
    }
}

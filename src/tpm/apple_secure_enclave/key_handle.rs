use std::collections::HashSet;

use async_trait::async_trait;
use security_framework::key::SecKey;

use crate::common::{
    config::{KeyPairSpec, KeySpec},
    error::SecurityModuleError,
    traits::key_handle::KeyPairHandleImpl,
};

struct AppleSecureEnclaveKeyPair {}

#[async_trait]
impl KeyPairHandleImpl for AppleSecureEnclaveKeyPair {
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        todo!()
    }

    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    async fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }
}

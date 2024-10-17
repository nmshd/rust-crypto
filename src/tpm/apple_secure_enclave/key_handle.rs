use std::collections::HashSet;

use async_trait::async_trait;
use base64::prelude::*;
use security_framework::key::Algorithm;
use security_framework::key::SecKey;

use crate::common::{
    config::{KeyPairSpec, KeySpec},
    error::SecurityModuleError,
    traits::key_handle::KeyPairHandleImpl,
};

pub(crate) struct AppleSecureEnclaveKeyPair {
    pub(super) key_handle: SecKey,
}

#[async_trait]
impl KeyPairHandleImpl for AppleSecureEnclaveKeyPair {
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        match self
            .key_handle
            .create_signature(Algorithm::ECDSASignatureDigestX962SHA256, data)
        {
            Ok(data) => Ok(data),
            Err(e) => Err(SecurityModuleError::SigningError(e.description())),
        }
    }

    async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        match self.key_handle.verify_signature(
            Algorithm::ECDSASignatureDigestX962SHA256,
            data,
            signature,
        ) {
            Ok(result) => Ok(result),
            Err(e) => Err(SecurityModuleError::SignatureVerificationError(
                e.description(),
            )),
        }
    }

    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        let public_key: SecKey = self
            .key_handle
            .public_key()
            .ok_or(SecurityModuleError::UnsupportedAlgorithm)?;
        let external_representation = public_key
            .external_representation()
            .ok_or(SecurityModuleError::UnsupportedAlgorithm)?;
        external_representation.bytes().clone()
    }

    async fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    fn id(&self) -> Result<String, SecurityModuleError> {
        match self.application_label() {
            None => Err(SecurityModuleError::KeyError),
            Some(bytes) => Ok(BASE64_STANDARD.encode(bytes)),
        }
    }
}

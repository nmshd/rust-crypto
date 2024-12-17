use std::fmt;

use base64::prelude::*;
use security_framework::key::Algorithm;
use security_framework::key::SecKey;
use tracing::instrument;

use crate::common::config::KeyPairSpec;
use crate::common::error::ToCalError;
use crate::common::{
    crypto::algorithms::hashes::CryptoHash,
    error::{CalError, KeyType},
    traits::key_handle::KeyPairHandleImpl,
    DHExchange,
};
use crate::storage::StorageManager;

#[instrument(level = "trace")]
fn hash_kind(hash: CryptoHash) -> Result<Algorithm, CalError> {
    match hash {
        CryptoHash::Sha2_224 => Ok(Algorithm::ECDSASignatureMessageX962SHA224),
        CryptoHash::Sha2_256 => Ok(Algorithm::ECDSASignatureMessageX962SHA256),
        CryptoHash::Sha2_384 => Ok(Algorithm::ECDSASignatureMessageX962SHA384),
        CryptoHash::Sha2_512 => Ok(Algorithm::ECDSASignatureMessageX962SHA512),
        _ => Err(CalError::bad_parameter(
            "Only Sha2 is supported.".to_owned(),
            true,
            None,
        )),
    }
}

#[derive(Clone)]
pub(crate) struct AppleSecureEnclaveKeyPair {
    pub(super) key_handle: SecKey,
    pub(super) spec: KeyPairSpec,
    pub(super) storage_manager: Option<StorageManager>,
}

impl KeyPairHandleImpl for AppleSecureEnclaveKeyPair {
    #[instrument(level = "trace", skip(data))]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.key_handle
            .create_signature(hash_kind(self.spec.signing_hash)?, data)
            .err_internal()
    }

    #[instrument(level = "trace", skip(data, signature))]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        let public_key: SecKey = self.key_handle.public_key().ok_or(CalError::missing_key(
            "SecKeyCopyPublicKey returned NULL".to_owned(),
            KeyType::Public,
        ))?;
        public_key
            .verify_signature(hash_kind(self.spec.signing_hash)?, data, signature)
            .err_internal()
    }

    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    #[instrument(level = "trace", skip_all)]
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        let public_key: SecKey = self.key_handle.public_key().ok_or(CalError::missing_key(
            "SecKeyCopyPublicKey returned NULL".to_owned(),
            KeyType::Public,
        ))?;
        let external_representation =
            public_key
                .external_representation()
                .ok_or(CalError::missing_value(
                    "SecKeyCopyExternalRepresentation returned NULL".to_owned(),
                    false,
                    None,
                ))?;
        Ok(Vec::from(external_representation.bytes()))
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    #[instrument(level = "trace", skip_all)]
    fn id(&self) -> Result<String, CalError> {
        match self.key_handle.application_label() {
            None => Err(CalError::missing_value(
                "kSecAttrApplicationLabel missing for this key".to_owned(),
                false,
                None,
            )),
            Some(bytes) => Ok(BASE64_STANDARD.encode(bytes)),
        }
    }

    #[instrument]
    fn delete(self) -> Result<(), CalError> {
        if let Some(storage_manager) = &self.storage_manager {
            storage_manager.delete(self.id()?);
        }
        self.key_handle.delete().err_internal()
    }
}

impl fmt::Debug for AppleSecureEnclaveKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleSecureEnclaveKeyPair")
            .field("key_handle", &self.key_handle)
            .field("metadata", &self.spec)
            .finish()
    }
}

impl Drop for AppleSecureEnclaveKeyPair {
    fn drop(&mut self) {
        if self.storage_manager.is_none() {
            if let Err(e) = self.key_handle.delete() {
                tracing::warn!("Failed to delete ephemeral key on device: {:?}", e);
            }
        }
    }
}

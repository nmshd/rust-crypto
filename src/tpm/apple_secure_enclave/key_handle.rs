use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::prelude::*;
use pollster::block_on;
use security_framework::key::Algorithm;
use security_framework::key::SecKey;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::common::{
    crypto::algorithms::hashes::{CryptoHash, Sha2Bits},
    error::{CalError, KeyType, ToCalError},
    traits::key_handle::KeyPairHandleImpl,
    DHExchange,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct KeyPairMetadata {
    pub hash: CryptoHash,
}

impl KeyPairMetadata {
    #[instrument(level = "trace")]
    fn hash(&self) -> Result<Algorithm, CalError> {
        match self.hash {
            CryptoHash::Sha1 => Ok(Algorithm::ECDSASignatureMessageX962SHA1),
            CryptoHash::Sha2(bits) => match bits {
                Sha2Bits::Sha224 => Ok(Algorithm::ECDSASignatureMessageX962SHA224),
                Sha2Bits::Sha256 => Ok(Algorithm::ECDSASignatureMessageX962SHA256),
                Sha2Bits::Sha384 => Ok(Algorithm::ECDSASignatureMessageX962SHA384),
                Sha2Bits::Sha512 => Ok(Algorithm::ECDSASignatureMessageX962SHA512),
                _ => Err(CalError::bad_parameter(format!("{:#?}", bits), true, None)),
            },
            _ => Err(CalError::bad_parameter(
                "Only Sha1 and Sha2 are supported.".to_owned(),
                true,
                None,
            )),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AppleSecureEnclaveKeyPair {
    pub(super) key_handle: SecKey,
    pub(super) metadata: KeyPairMetadata,
    pub(super) del_fn:
        Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
}

impl KeyPairHandleImpl for AppleSecureEnclaveKeyPair {
    #[instrument(level = "trace", skip(data))]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.key_handle
            .create_signature(self.metadata.hash()?, data)
            .err_internal()
    }

    #[instrument(level = "trace", skip(data, signature))]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        let public_key: SecKey = self.key_handle.public_key().ok_or(CalError::missing_key(
            "SecKeyCopyPublicKey returned NULL".to_owned(),
            KeyType::Public,
        ))?;
        public_key
            .verify_signature(self.metadata.hash()?, data, signature)
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
        block_on((*self.del_fn)(self.id()?));
        self.key_handle.delete().err_internal()
    }
}

impl fmt::Debug for AppleSecureEnclaveKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleSecureEnclaveKeyPair")
            .field("key_handle", &self.key_handle)
            .field("metadata", &self.metadata)
            .finish()
    }
}

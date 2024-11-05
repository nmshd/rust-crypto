use base64::prelude::*;
use security_framework::key::Algorithm;
use security_framework::key::SecKey;

use crate::common::{
    error::{CalError, KeyType, ToCalError},
    traits::key_handle::KeyPairHandleImpl,
    DHExchange,
};

#[derive(Debug, Clone)]
pub(crate) struct AppleSecureEnclaveKeyPair {
    pub(super) key_handle: SecKey,
}

impl KeyPairHandleImpl for AppleSecureEnclaveKeyPair {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.key_handle
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, data)
            .err_internal()
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        let public_key: SecKey = self.key_handle.public_key().ok_or(CalError::missing_key(
            "SecKeyCopyPublicKey returned NULL".to_owned(),
            KeyType::Public,
        ))?;
        public_key
            .verify_signature(Algorithm::ECDSASignatureMessageX962SHA256, data, signature)
            .err_internal()
    }

    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

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

    fn delete(self) -> Result<(), CalError> {
        match self.key_handle.delete() {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

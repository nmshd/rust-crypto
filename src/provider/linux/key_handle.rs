use crate::{
    common::{traits::key_handle::KeyHandleImpl, KeyHandle},
    prelude::{CalError, KeySpec},
    storage::StorageManager,
};

#[derive(Clone, Debug)]
pub(crate) struct LinuxKeyHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeySpec,
    pub(crate) storage_manager: Option<StorageManager>,
}

impl KeyHandleImpl for LinuxKeyHandle {
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        Err(CalError::not_implemented())
    }

    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn hmac(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn verify_hmac(&self, data: &[u8], hmac: &[u8]) -> Result<bool, CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id)
    }

    fn delete(self) -> Result<(), CalError> {
        Err(CalError::not_implemented())
    }

    fn spec(&self) -> KeySpec {
        self.spec
    }
}

use crate::{
    common::{traits::key_handle::KeyPairHandleImpl, DHExchange},
    prelude::{CalError, KeyPairSpec},
    storage::StorageManager,
};

#[derive(Clone, Debug)]
pub(crate) struct LinuxKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) storage_manager: Option<StorageManager>,
}

impl KeyPairHandleImpl for LinuxKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        Err(CalError::not_implemented())
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    fn delete(self) -> Result<(), CalError> {
        Err(CalError::not_implemented())
    }

    fn spec(&self) -> KeyPairSpec {
        self.spec
    }
}

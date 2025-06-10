use std::sync::Arc;

use crate::{
    common::KeyHandle,
    storage::{
        encryption::{EncryptionBackend, EncryptionBackendError},
        StorageField,
    },
};

#[derive(Debug, Clone)]
pub struct KeyHandleBackend {
    key_handle: Arc<KeyHandle>,
}

impl EncryptionBackend for KeyHandleBackend {
    fn encrypt(&self, data: &[u8]) -> Result<StorageField, super::EncryptionBackendError> {
        let (data, iv) = self
            .key_handle
            .encrypt(data)
            .map_err(|e| EncryptionBackendError::Encrypt { source: e })?;

        Ok(StorageField::Encrypted { data, iv })
    }

    fn decrypt(&self, cipher: StorageField) -> Result<Vec<u8>, EncryptionBackendError> {
        match cipher {
            StorageField::Encrypted { data, iv } => self
                .key_handle
                .decrypt_data(&data, &iv)
                .map_err(|e| EncryptionBackendError::Decrypt { source: e }),
            _ => Err(EncryptionBackendError::WrongStorageField),
        }
    }
}

use std::rc::Rc;

use crate::{
    common::KeyPairHandle,
    storage::{encryption::EncryptionBackend, StorageField},
};

#[derive(Debug, Clone)]
pub struct KeyPairHandleBackend {
    key_pair_handle: Rc<KeyPairHandle>,
}

impl EncryptionBackend for KeyPairHandleBackend {
    fn encrypt(&self, data: &[u8]) -> Result<StorageField, super::EncryptionBackendError> {
        let data = self
            .key_pair_handle
            .encrypt_data(data)
            .map_err(|e| super::EncryptionBackendError::Encrypt { source: e })?;

        Ok(StorageField::EncryptedAsymmetric { data })
    }

    fn decrypt(&self, cipher: StorageField) -> Result<Vec<u8>, super::EncryptionBackendError> {
        match cipher {
            StorageField::EncryptedAsymmetric { data } => self
                .key_pair_handle
                .decrypt_data(&data)
                .map_err(|e| super::EncryptionBackendError::Decrypt { source: e }),
            _ => Err(super::EncryptionBackendError::WrongStorageField),
        }
    }
}

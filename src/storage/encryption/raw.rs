use crate::storage::{encryption::EncryptionBackend, StorageField};

pub struct RawBackend {}

impl EncryptionBackend for RawBackend {
    fn decrypt(
        &self,
        cipher: crate::storage::StorageField,
    ) -> Result<Vec<u8>, super::EncryptionBackendError> {
        match cipher {
            StorageField::Raw(data) => Ok(data),
            _ => Err(super::EncryptionBackendError::WrongStorageField),
        }
    }

    fn encrypt(&self, data: &[u8]) -> Result<StorageField, super::EncryptionBackendError> {
        Ok(StorageField::Raw(data.to_vec()))
    }
}

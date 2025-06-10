use thiserror::Error;

use crate::{prelude::CalError, storage::StorageField};

mod key_handle;
mod key_pair_handle;

#[derive(Debug, Error)]
pub enum EncryptionBackendError {
    #[error("Failed encryption.")]
    Encrypt { source: CalError },
    #[error("Failed decryption.")]
    Decrypt { source: CalError },
    #[error("The cipher text to be decrypted by the storage manager encryption backend does not match what the storage field that was expected.")]
    WrongStorageField,
}

pub trait EncryptionBackend {
    fn encrypt(&self, data: &[u8]) -> Result<StorageField, EncryptionBackendError>;

    fn decrypt(&self, cipher: StorageField) -> Result<Vec<u8>, EncryptionBackendError>;
}

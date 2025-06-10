use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::{
    prelude::CalError,
    storage::{
        encryption::{
            key_handle::KeyHandleBackend, key_pair_handle::KeyPairHandleBackend, raw::RawBackend,
        },
        StorageField,
    },
};

mod key_handle;
mod key_pair_handle;
mod raw;

#[derive(Debug, Error)]
pub enum EncryptionBackendError {
    #[error("Failed encryption.")]
    Encrypt { source: CalError },
    #[error("Failed decryption.")]
    Decrypt { source: CalError },
    #[error("The cipher text to be decrypted by the storage manager encryption backend does not match what the storage field that was expected.")]
    WrongStorageField,
}

#[enum_dispatch]
pub trait EncryptionBackend {
    fn encrypt(&self, data: &[u8]) -> Result<StorageField, EncryptionBackendError>;

    fn decrypt(&self, cipher: StorageField) -> Result<Vec<u8>, EncryptionBackendError>;
}

#[enum_dispatch(EncryptionBackend)]
#[derive(Debug, Clone)]
pub enum EncryptionBackendExplicit {
    KeyPairHandleBackend,
    KeyHandleBackend,
    RawBackend,
}

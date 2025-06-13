use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use thiserror::Error;

use crate::{
    prelude::{AdditionalConfig, CalError},
    storage::{
        encryption::{
            key_handle::KeyHandleBackend, key_pair_handle::KeyPairHandleBackend, raw::RawBackend,
        },
        StorageField, StorageManagerInitializationError,
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
    #[error("The cipher text to be decrypted by the storage manager encryption backend does not match what the expected storage field.")]
    WrongStorageField,
    #[error("Failed to get scope.")]
    Scope { source: CalError },
}

#[enum_dispatch]
pub trait EncryptionBackend {
    fn encrypt(&self, data: &[u8]) -> Result<StorageField, EncryptionBackendError>;

    fn decrypt(&self, cipher: StorageField) -> Result<Vec<u8>, EncryptionBackendError>;

    fn scope(&self) -> Result<String, EncryptionBackendError>;
}

#[enum_dispatch(EncryptionBackend)]
#[derive(Debug, Clone)]
pub enum EncryptionBackendExplicit {
    KeyPairHandleBackend,
    KeyHandleBackend,
    RawBackend,
}

impl EncryptionBackendExplicit {
    pub fn new(config: &[AdditionalConfig]) -> Result<Self, StorageManagerInitializationError> {
        Ok(
            config.iter()
            .filter_map(|e| match e {
                AdditionalConfig::StorageConfigSymmetricEncryption(handle) => {
                    Some(Self::from(KeyHandleBackend::new(handle.clone())))
                }
                AdditionalConfig::StorageConfigAsymmetricEncryption(handle) => {
                    Some(Self::from(KeyPairHandleBackend::new(handle.clone())))
                }
                _ => None,
            })
            .at_most_one()
            .map_err(|_| StorageManagerInitializationError::ConflictingProviderImplConfig { 
                description: "Expected either StorageConfigSymmetricEncryption OR StorageConfigAsymmetricEncryption, not both." 
            })?
            .unwrap_or_else(|| Self::from(RawBackend {}))
        )
    }
}

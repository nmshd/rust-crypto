use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::{
    prelude::{AdditionalConfig, CalError, ProviderImplConfig},
    storage::{
        encryption::{
            key_handle::KeyHandleBackend, key_pair_handle::KeyPairHandleBackend, raw::RawBackend,
        },
        StorageField, StorageManagerError,
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

impl EncryptionBackendExplicit {
    pub fn new(provider_impl_config: &ProviderImplConfig) -> Result<Self, StorageManagerError> {
        let mut encryption_backends =
            provider_impl_config
                .additional_config
                .iter()
                .filter_map(|e| match e {
                    AdditionalConfig::StorageConfigSymmetricEncryption(handle) => {
                        Some(Self::from(KeyHandleBackend::new(handle.clone())))
                    }
                    AdditionalConfig::StorageConfigAsymmetricEncryption(handle) => {
                        Some(Self::from(KeyPairHandleBackend::new(handle.clone())))
                    }
                    _ => None,
                });

        let encryption_backend = encryption_backends
            .next()
            .unwrap_or_else(|| Self::from(RawBackend {}));

        if encryption_backends.next().is_some() {
            Err(StorageManagerError::ConflictingProviderImplConfig { description: "Expected either StorageConfigSymmetricEncryption OR StorageConfigAsymmetricEncryption, not both." })
        } else {
            Ok(encryption_backend)
        }
    }
}

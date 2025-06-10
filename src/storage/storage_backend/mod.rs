use std::fmt::Debug;

use enum_dispatch::enum_dispatch;
use thiserror::Error;

mod file_store;
mod kv_store;

use file_store::FileStorageBackend;
use kv_store::KvStorageBackend;

use crate::{prelude::AdditionalConfig, storage::StorageManagerError};

#[derive(Debug, Error)]
pub enum StorageBackendError {
    #[error("Failed to store data: {description}")]
    Store {
        description: &'static str,
        source: anyhow::Error,
    },
    #[error("Failed to store data. Cause unknown.")]
    StoreUnknown,
    #[error("Failed to get data: {description}")]
    Get {
        description: &'static str,
        source: anyhow::Error,
    },
    #[error("Failed to get data. Cause unknown.")]
    GetUnknown,
    #[error("Failed to decode key.")]
    KeyDecode { source: anyhow::Error },
    #[error("Failed to open storage backend: {description}")]
    Open {
        description: &'static str,
        source: anyhow::Error,
    },
    #[error("Key or data for key does not exist in storage backend.")]
    NotExists,
    #[error("Failed to delete key for storage backend: {description}")]
    Delete {
        description: &'static str,
        source: anyhow::Error,
    },
}

#[enum_dispatch]
pub trait StorageBackend: Debug {
    fn store(&self, key: String, data: &[u8]) -> Result<(), StorageBackendError>;
    fn get(&self, key: String) -> Result<Vec<u8>, StorageBackendError>;
    fn delete(&self, key: String) -> Result<(), StorageBackendError>;
    fn keys(&self) -> Result<Vec<String>, StorageBackendError>;
}

#[enum_dispatch(StorageBackend)]
#[derive(Clone)]
pub enum StorageBackendExplicit {
    FileStorageBackend,
    KvStorageBackend,
}

impl Debug for StorageBackendExplicit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageBackendExplicit::KvStorageBackend(_) => {
                f.debug_struct("KvStorageBackend").finish()
            }
            StorageBackendExplicit::FileStorageBackend(file) => writeln!(f, "{:?}", file),
        }
    }
}

impl StorageBackendExplicit {
    pub fn new(config: &[AdditionalConfig]) -> Result<Self, StorageManagerError> {
        let filtered_config: Vec<&AdditionalConfig> = config
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    AdditionalConfig::FileStoreConfig { .. }
                        | AdditionalConfig::KVStoreConfig { .. }
                )
            })
            .collect();

        match filtered_config.len() {
            0 => {
                return Err(StorageManagerError::MissingProviderImplConfigOption {
                    description:
                        "No additional config for initializing a storage backend was given.",
                })
            }
            2.. => {
                return Err(StorageManagerError::ConflictingProviderImplConfig {
                    description: "Expected either FileStoreConfig OR KVStoreConfig, not both.",
                })
            }
            1 => {}
        }

        match filtered_config[0] {
            AdditionalConfig::FileStoreConfig { db_dir } => FileStorageBackend::new(db_dir)
                .map_err(|e| StorageManagerError::InitializingStorageBackend {
                    source: e,
                    description: "Failed to initialize the file storage backend.",
                })
                .map(Self::from),

            AdditionalConfig::KVStoreConfig {
                get_fn,
                store_fn,
                delete_fn,
                all_keys_fn,
            } => Ok(Self::from(KvStorageBackend {
                get_fn: get_fn.clone(),
                store_fn: store_fn.clone(),
                delete_fn: delete_fn.clone(),
                all_keys_fn: all_keys_fn.clone(),
            })),
            _ => unreachable!(),
        }
    }
}

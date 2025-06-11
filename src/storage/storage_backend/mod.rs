use std::fmt::Debug;

use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use thiserror::Error;

mod file_store;
mod kv_store;

use file_store::FileStorageBackend;
use kv_store::KvStorageBackend;

use crate::{
    prelude::AdditionalConfig,
    storage::{key::ScopedKey, StorageManagerError},
};

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
    #[error("Failed operation regarding scoped keys: {description}")]
    Scope {
        description: &'static str,
        source: anyhow::Error,
    },
}

#[enum_dispatch]
pub trait StorageBackend: Debug {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError>;
    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError>;
    fn delete(&self, key: ScopedKey) -> Result<(), StorageBackendError>;
    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>>;
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
        let file_store = |db_dir: &String| {
            FileStorageBackend::new(db_dir)
                .map_err(|e| StorageManagerError::InitializeStorageBackend {
                    source: e,
                    description: "Failed to initialize the file storage backend.",
                })
                .map(Self::from)
        };

        let storage_backend_option_from_additional_config =
            |additional_data: &AdditionalConfig| match additional_data {
                AdditionalConfig::FileStoreConfig { db_dir } => Some(file_store(db_dir)),
                AdditionalConfig::KVStoreConfig {
                    get_fn,
                    store_fn,
                    delete_fn,
                    all_keys_fn,
                } => Some(Ok(Self::from(KvStorageBackend {
                    get_fn: get_fn.clone(),
                    store_fn: store_fn.clone(),
                    delete_fn: delete_fn.clone(),
                    all_keys_fn: all_keys_fn.clone(),
                }))),
                _ => None,
            };

        // `count` is either `1` or `2..`.
        let error_from_count = |count: usize| {
            if count > 1 {
                StorageManagerError::ConflictingProviderImplConfig {
                    description: "Expected either FileStoreConfig OR KVStoreConfig, not both.",
                }
            } else {
                StorageManagerError::MissingProviderImplConfigOption {
                    description:
                        "No additional config for initializing a storage backend was given.",
                }
            }
        };

        config
            .iter()
            .filter_map(storage_backend_option_from_additional_config)
            .exactly_one()
            .map_err(|iter| error_from_count(iter.count()))?
    }
}

use std::fmt::Debug;

use enum_dispatch::enum_dispatch;
use thiserror::Error;

mod file_store;
mod kv_store;

use file_store::FileStorageBackend;
use kv_store::KvStorageBackend;

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

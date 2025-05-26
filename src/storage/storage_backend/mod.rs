use thiserror::Error;

mod file_store;
mod kv_store;

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

pub trait StorageBackend: Sync {
    fn store(&self, key: &[u8], data: &[u8]) -> Result<(), StorageBackendError>;
    fn get(&self, key: &[u8]) -> Result<Vec<u8>, StorageBackendError>;
    fn delete(&self, key: &[u8]) -> Result<(), StorageBackendError>;
    fn keys(&self) -> Result<Vec<Vec<u8>>, StorageBackendError>;
}

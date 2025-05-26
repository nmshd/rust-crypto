use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageBackendError {
    #[error("Failed to store data. Cause unknown.")]
    StoreUnknown,
    #[error("Failed to get data. Cause unknown.")]
    GetUnknown,
    #[error("Failed to decode key.")]
    KeyDecode { source: anyhow::Error },
}

pub trait StorageBackend: Sync {
    fn store(&mut self, key: &[u8], data: &[u8]) -> Result<(), StorageBackendError>;
    fn get(&self, key: &[u8]) -> Result<Vec<u8>, StorageBackendError>;
    fn delete(&mut self, key: &[u8]) -> Result<(), StorageBackendError>;
    fn keys(&self) -> Result<Vec<Vec<u8>>, StorageBackendError>;
}

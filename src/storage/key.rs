use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageManagerKeyError {
    #[error("Failed to deserialize value to StorageManagerKey.")]
    Deserialize { source: anyhow::Error },
    #[error("Failed to serialize StorageManagerKey.")]
    Serialize { source: anyhow::Error },
}

/// Key that is used to store, get and delete data from a `StorageManagerBackend`.
///
/// This key stores the key id of the key handle, that the stored data is from.
/// Provider name and security key id are used as scope, so that different providers
/// or providers with different metadata security may never accidentally access the same keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageManagerKey {
    pub key_id: String,
    pub provider_name: String,
    pub security_key_id: Option<String>,
}

impl StorageManagerKey {
    pub fn serialize(&self) -> Result<String, StorageManagerKeyError> {
        to_string(self).map_err(|e| StorageManagerKeyError::Serialize { source: anyhow!(e) })
    }

    pub fn deserialize(value: &String) -> Result<Self, StorageManagerKeyError> {
        from_str(value).map_err(|e| StorageManagerKeyError::Deserialize { source: anyhow!(e) })
    }
}

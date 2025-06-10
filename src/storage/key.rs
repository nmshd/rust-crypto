use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};
use thiserror::Error;

use crate::storage::StorageManagerError;

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
/// Provider name, encryption and signature backend scope are used as scope, so that different providers
/// or providers with different metadata security may never accidentally access the same keys.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageManagerKey {
    pub key_id: String,
    pub provider_scope: String,
    pub encryption_scope: String,
    pub signature_scope: String,
}

impl StorageManagerKey {
    pub fn serialize(&self) -> Result<String, StorageManagerKeyError> {
        to_string(self).map_err(|e| StorageManagerKeyError::Serialize { source: anyhow!(e) })
    }

    pub fn deserialize(value: &String) -> Result<Self, StorageManagerKeyError> {
        from_str(value).map_err(|e| StorageManagerKeyError::Deserialize { source: anyhow!(e) })
    }
}

#[derive(Debug, Clone)]
pub struct StorageManagerKeyFactory {
    pub provider_scope: String,
    pub encryption_scope: String,
    pub signature_scope: String,
}

impl StorageManagerKeyFactory {
    pub fn scoped_key(&self, key_id: impl Into<String>) -> Result<String, StorageManagerError> {
        StorageManagerKey {
            key_id: key_id.into(),
            provider_scope: self.provider_scope.clone(),
            encryption_scope: self.encryption_scope.clone(),
            signature_scope: self.signature_scope.clone(),
        }
        .serialize()
        .map_err(|e| StorageManagerError::Scope { source: anyhow!(e) })
    }
}

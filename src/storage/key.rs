use anyhow::anyhow;
use rmp_serde::{from_slice, to_vec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Key that is used to store, get and delete data from a `StorageManagerBackend`.
///
/// This key stores the key id of the key handle, that the stored data is from.
/// Provider name and security key id are used as scope, so that different providers
/// or providers with different metadata security may never accidentally access the same keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageManagerKey {
    pub key_id: Vec<u8>,
    pub provider_name: String,
    pub security_key_id: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum StorageManagerKeyError {
    #[error("Failed to deserialize value to StorageManagerKey.")]
    Deserialize { source: anyhow::Error },
    #[error("Failed to serialize StorageManagerKey.")]
    Serialize { source: anyhow::Error },
}

impl TryFrom<&[u8]> for StorageManagerKey {
    type Error = StorageManagerKeyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        from_slice(value).map_err(|err| StorageManagerKeyError::Deserialize {
            source: anyhow!(err),
        })
    }
}

impl TryInto<Vec<u8>> for StorageManagerKey {
    type Error = StorageManagerKeyError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        to_vec(&self).map_err(|err| StorageManagerKeyError::Serialize {
            source: anyhow!(err),
        })
    }
}

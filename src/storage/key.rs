use serde::{Deserialize, Serialize};

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

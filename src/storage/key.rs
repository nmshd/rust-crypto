use serde::{Deserialize, Serialize};

/// Key that is used to store, get and delete data from a `StorageManagerBackend`.
///
/// This key stores the key id of the key handle, that the stored data is from.
/// Provider name, encryption and signature backend scope are used as scope, so that different providers
/// or providers with different metadata security may never accidentally access the same keys.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScopedKey {
    pub key_id: String,
    pub provider_scope: String,
    pub encryption_scope: String,
    pub signature_scope: String,
}

#[derive(Debug, Clone)]
pub struct ScopedKeyFactory {
    pub provider_scope: String,
    pub encryption_scope: String,
    pub signature_scope: String,
}

impl ScopedKeyFactory {
    pub fn scoped_key(&self, key_id: impl Into<String>) -> ScopedKey {
        ScopedKey {
            key_id: key_id.into(),
            provider_scope: self.provider_scope.clone(),
            encryption_scope: self.encryption_scope.clone(),
            signature_scope: self.signature_scope.clone(),
        }
    }
}

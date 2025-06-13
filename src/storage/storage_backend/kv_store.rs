use std::fmt::Debug;

use thiserror::Error;

use crate::{
    common::config::{AllKeysFn, DeleteFn, GetFn, StoreFn},
    storage::key::ScopedKey,
};

use super::{StorageBackend, StorageBackendError};

#[derive(Debug, Error)]
pub enum KvStorageBackendError {
    #[error("Failed to serialize scoped key to json.")]
    ScopeSerialize { source: serde_json::Error },
    #[error("Failed to deserialize json to scoped key.")]
    ScopeDeserialize { source: serde_json::Error },
    #[error("Failed to store data. Cause unknown.")]
    Store,
    #[error("Failed to get data. Cause unknown.")]
    Get,
}

#[derive(Clone)]
pub struct KvStorageBackend {
    pub get_fn: GetFn,
    pub store_fn: StoreFn,
    pub delete_fn: DeleteFn,
    pub all_keys_fn: AllKeysFn,
}

fn serialize_scoped_key(key: ScopedKey) -> Result<String, StorageBackendError> {
    serde_json::to_string(&key)
        .map_err(|err| KvStorageBackendError::ScopeSerialize { source: err }.into())
}

fn deserialize_scoped_key(value: &str) -> Result<ScopedKey, StorageBackendError> {
    serde_json::from_str(value)
        .map_err(|err| KvStorageBackendError::ScopeDeserialize { source: err }.into())
}

impl StorageBackend for KvStorageBackend {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(key)?;
        if pollster::block_on((self.store_fn)(key, data.to_owned())) {
            Ok(())
        } else {
            Err(KvStorageBackendError::Store.into())
        }
    }

    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
        let key = serialize_scoped_key(key)?;
        pollster::block_on((self.get_fn)(key)).ok_or_else(|| KvStorageBackendError::Get.into())
    }

    fn delete(&self, key: ScopedKey) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(key)?;
        Ok(pollster::block_on((self.delete_fn)(key)))
    }

    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>> {
        let keys = pollster::block_on((self.all_keys_fn)());

        keys.into_iter()
            .map(|s| deserialize_scoped_key(&s))
            .collect()
    }
}

impl Debug for KvStorageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StorageBackend {{ .. }}")
    }
}

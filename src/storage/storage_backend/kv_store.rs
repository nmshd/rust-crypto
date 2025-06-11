use std::fmt::Debug;

use anyhow::anyhow;

use crate::{
    common::config::{AllKeysFn, DeleteFn, GetFn, StoreFn},
    storage::key::ScopedKey,
};

use super::{StorageBackend, StorageBackendError};

#[derive(Clone)]
pub struct KvStorageBackend {
    pub get_fn: GetFn,
    pub store_fn: StoreFn,
    pub delete_fn: DeleteFn,
    pub all_keys_fn: AllKeysFn,
}

fn serialize_scoped_key(key: ScopedKey) -> Result<String, StorageBackendError> {
    serde_json::to_string(&key).map_err(|err| StorageBackendError::Scope {
        description: "Failed to serialize scoped key.",
        source: anyhow!(err),
    })
}

fn deserialize_scoped_key(value: &str) -> Result<ScopedKey, StorageBackendError> {
    serde_json::from_str(value).map_err(|err| StorageBackendError::Scope {
        description: "Failed to deserialize scoped key.",
        source: anyhow!(err),
    })
}

impl StorageBackend for KvStorageBackend {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(key)?;
        if pollster::block_on((self.store_fn)(key, data.to_owned())) {
            Ok(())
        } else {
            Err(StorageBackendError::StoreUnknown)
        }
    }

    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
        let key = serialize_scoped_key(key)?;
        pollster::block_on((self.get_fn)(key)).ok_or_else(|| StorageBackendError::GetUnknown)
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

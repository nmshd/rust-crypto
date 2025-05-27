use anyhow::anyhow;
use base64::prelude::*;

use crate::common::config::{AllKeysFn, DeleteFn, GetFn, StoreFn};

use super::{StorageBackend, StorageBackendError};

fn encode_key(key: &[u8]) -> String {
    BASE64_URL_SAFE.encode(key)
}

fn decode_key(encoded_key: String) -> Result<Vec<u8>, StorageBackendError> {
    BASE64_URL_SAFE
        .decode(encoded_key)
        .map_err(|e| StorageBackendError::KeyDecode { source: anyhow!(e) })
}

#[derive(Clone)]
pub struct KvStorageBackend {
    pub get_fn: GetFn,
    pub store_fn: StoreFn,
    pub delete_fn: DeleteFn,
    pub all_keys_fn: AllKeysFn,
}

impl StorageBackend for KvStorageBackend {
    fn store(&self, key: String, data: &[u8]) -> Result<(), StorageBackendError> {
        if pollster::block_on((self.store_fn)(key, data.to_owned())) {
            Ok(())
        } else {
            Err(StorageBackendError::StoreUnknown)
        }
    }

    fn get(&self, key: String) -> Result<Vec<u8>, StorageBackendError> {
        pollster::block_on((self.get_fn)(key)).ok_or_else(|| StorageBackendError::GetUnknown)
    }

    fn delete(&self, key: String) -> Result<(), StorageBackendError> {
        Ok(pollster::block_on((self.delete_fn)(key)))
    }

    fn keys(&self) -> Result<Vec<String>, StorageBackendError> {
        let keys = pollster::block_on((self.all_keys_fn)());

        Ok(keys)
    }
}

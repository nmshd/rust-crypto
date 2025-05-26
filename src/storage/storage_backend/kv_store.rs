use anyhow::anyhow;
use base64::prelude::*;
use itertools::{Either, Itertools};

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
    fn store(&self, key: &[u8], data: &[u8]) -> Result<(), StorageBackendError> {
        if pollster::block_on((self.store_fn)(encode_key(key), data.to_owned())) {
            Ok(())
        } else {
            Err(StorageBackendError::StoreUnknown)
        }
    }

    fn get(&self, key: &[u8]) -> Result<Vec<u8>, StorageBackendError> {
        pollster::block_on((self.get_fn)(encode_key(key)))
            .ok_or_else(|| StorageBackendError::GetUnknown)
    }

    fn delete(&self, key: &[u8]) -> Result<(), StorageBackendError> {
        Ok(pollster::block_on((self.delete_fn)(encode_key(key))))
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>, StorageBackendError> {
        let keys = pollster::block_on((self.all_keys_fn)());

        let (decoded_keys, mut errors): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .map(|e| decode_key(e))
            .partition_map(|e| match e {
                Ok(key) => Either::Left(key),
                Err(err) => Either::Right(err),
            });

        if let Some(err) = errors.pop() {
            Err(err)
        } else {
            Ok(decoded_keys)
        }
    }
}

use std::fmt;

use tracing::trace;

use crate::{
    common::{
        config::{AllKeysFn, DeleteFn, GetFn, StoreFn},
        error::KeyType,
    },
    prelude::CalError,
};

#[derive(Clone)]
pub struct KVStore {
    pub get_fn: GetFn,
    pub store_fn: StoreFn,
    pub delete_fn: DeleteFn,
    pub all_keys_fn: AllKeysFn,
}

impl fmt::Debug for KVStore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KVStore {{}}")
    }
}

impl KVStore {
    pub fn store(
        &self,
        scope: impl AsRef<str>,
        key: impl AsRef<str>,
        value: Vec<u8>,
    ) -> Result<(), CalError> {
        let valid = pollster::block_on((self.store_fn)(
            format!("{}:{}", scope.as_ref(), key.as_ref()),
            value,
        ));
        if valid {
            Ok(())
        } else {
            Err(CalError::failed_operation(
                "Storing key failed, the handle may still be valid".to_owned(),
                false,
                None,
            ))
        }
    }

    pub fn get(&self, scope: impl AsRef<str>, key: impl AsRef<str>) -> Result<Vec<u8>, CalError> {
        let value = pollster::block_on((self.get_fn)(format!(
            "{}:{}",
            scope.as_ref(),
            key.as_ref()
        )));
        match value {
            Some(data) => Ok(data),
            None => Err(CalError::missing_key(key.as_ref(), KeyType::Private)),
        }
    }

    pub fn delete(&self, scope: impl AsRef<str>, key: impl AsRef<str>) {
        pollster::block_on((self.delete_fn)(format!(
            "{}:{}",
            scope.as_ref(),
            key.as_ref()
        )));
    }

    pub fn get_all_keys(&self, scope: String) -> Vec<Vec<u8>> {
        let keys = pollster::block_on((self.all_keys_fn)());
        trace!("get_all_keys_kv: {:?}", keys);
        keys.into_iter()
            .filter(|k| k.starts_with(&format!("{}:", scope.clone())))
            .map(|k| k.split(':').last().unwrap().to_owned())
            .filter_map(|k| self.get(scope.clone(), k).ok())
            .collect()
    }
}

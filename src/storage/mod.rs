use std::fmt;

use serde::{Deserialize, Serialize};

use crate::common::{
    config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, KeyPairSpec, KeySpec, StoreFn},
    error::{CalError, KeyType},
    KeyHandle,
};

fn invert<T, E>(x: Option<Result<T, E>>) -> Result<Option<T>, E> {
    x.map_or(Ok(None), |v| v.map(Some))
}

#[derive(Clone, Debug)]
pub(crate) struct StorageManager {
    key_handle: Option<Box<KeyHandle>>,
    db_store: Option<FileStore>,
    kv_store: Option<KVStore>,
    scope: String,
}

impl StorageManager {
    pub(crate) fn new(scope: String, config: &[AdditionalConfig]) -> Self {
        let db_store = config
            .iter()
            .filter_map(|c| {
                if let AdditionalConfig::FileStoreConfig {
                    db_path,
                    secure_path,
                    pass,
                } = c.clone()
                {
                    Some(FileStore {
                        db_path,
                        secure_path,
                        pass,
                    })
                } else {
                    None
                }
            })
            .last();
        let kv_store = config
            .iter()
            .filter_map(|c| {
                if let AdditionalConfig::KVStoreConfig {
                    get_fn,
                    store_fn,
                    delete_fn,
                    all_keys_fn,
                } = c.clone()
                {
                    Some(KVStore {
                        get_fn,
                        store_fn,
                        delete_fn,
                        all_keys_fn,
                    })
                } else {
                    None
                }
            })
            .last();

        let key_handle = config
            .iter()
            .filter_map(|c| {
                if let AdditionalConfig::StorageConfig { key_handle } = c {
                    Some(key_handle.clone())
                } else {
                    None
                }
            })
            .last();
        StorageManager {
            key_handle: key_handle.map(Box::new),
            db_store,
            kv_store,
            scope,
        }
    }

    pub(crate) fn store(&self, id: String, data: KeyData) -> Result<(), CalError> {
        // encrypt secret data if KeyHandle is available
        let mut data = data.clone();
        data.secret_data = invert(
            data.secret_data
                .map(|secret| match secret {
                    StorageField::Raw(v) => self.key_handle.as_ref().and_then(|key| {
                        let (v, iv) = match key.encrypt_data(&v) {
                            Ok(v) => v,
                            Err(e) => return Some(Err(e)),
                        };
                        Some(Ok(StorageField::Encryped { data: v, iv }))
                    }),
                    sf @ StorageField::Encryped { data: _, iv: _ } => Some(Ok(sf)),
                })
                .flatten(),
        )?;

        // choose storage Strategy
        match self {
            &StorageManager {
                key_handle: _,
                db_store: Some(ref db_store),
                kv_store: _,
                ref scope,
            } => db_store.store(scope.clone(), id, data),
            &StorageManager {
                key_handle: _,
                db_store: _,
                kv_store: Some(ref kv_store),
                ref scope,
            } => kv_store.store(scope.clone(), id, data),
            _ => {
                return Err(CalError::failed_operation(
                    "neither KV Store nor DB store were initialised".to_owned(),
                    true,
                    None,
                ))
            }
        }
    }

    pub(crate) fn get(&self, id: String) -> Result<KeyData, CalError> {
        // try all available storage methods
        if self.db_store.is_some() {
            if let Ok(v) = self
                .db_store
                .as_ref()
                .unwrap()
                .get(self.scope.clone(), id.clone())
            {
                return Ok(v);
            }
        }

        if self.kv_store.is_some() {
            if let Ok(v) = self
                .kv_store
                .as_ref()
                .unwrap()
                .get(self.scope.clone(), id.clone())
            {
                return Ok(v);
            }
        }

        Err(CalError::missing_key(
            format!("{}:{id}", self.scope),
            KeyType::Private,
        ))
    }

    pub(crate) fn delete(&self, id: String) {
        // try all available storage methods
        if self.db_store.is_some() {
            self.db_store
                .as_ref()
                .unwrap()
                .delete(self.scope.clone(), id.clone())
        }

        if self.kv_store.is_some() {
            self.kv_store
                .as_ref()
                .unwrap()
                .delete(self.scope.clone(), id.clone())
        }
    }
}

#[derive(Clone)]
struct KVStore {
    get_fn: GetFn,
    store_fn: StoreFn,
    delete_fn: DeleteFn,
    all_keys_fn: AllKeysFn,
}

impl fmt::Debug for KVStore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KVStore {{}}")
    }
}

impl KVStore {
    fn store(&self, provider: String, key: String, value: KeyData) -> Result<(), CalError> {
        let value = serde_json::to_vec(&value).unwrap();
        let valid = pollster::block_on((self.store_fn)(format!("{}:{}", provider, key), value));
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

    fn get(&self, provider: String, key: String) -> Result<KeyData, CalError> {
        let value = pollster::block_on((self.get_fn)(format!("{}:{}", provider, key)));
        match value {
            Some(data) => {
                let value: KeyData = serde_json::from_slice(&data).unwrap();
                Ok(value)
            }
            None => Err(CalError::missing_key(key, KeyType::Private)),
        }
    }

    fn delete(&self, provider: String, key: String) {
        pollster::block_on((self.delete_fn)(format!("{}:{}", provider, key)));
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct FileStore {
    db_path: String,
    secure_path: String,
    pass: String,
}

impl FileStore {
    fn store(&self, _provider: String, _key: String, _value: KeyData) -> Result<(), CalError> {
        todo!()
    }

    fn get(&self, _provider: String, _key: String) -> Result<KeyData, CalError> {
        todo!()
    }

    fn delete(&self, _provider: String, _key: String) {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum Spec {
    KeySpec(KeySpec),
    KeyPairSpec(KeyPairSpec),
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeyData {
    pub(crate) id: String,
    pub(crate) secret_data: Option<StorageField>,
    pub(crate) public_data: Option<Vec<u8>>,
    pub(crate) additional_data: Option<Vec<u8>>,
    pub(crate) spec: Spec,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum StorageField {
    Encryped { data: Vec<u8>, iv: Vec<u8> },
    Raw(Vec<u8>),
}

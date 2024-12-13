use std::fmt;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use sled::{open, Db};
use tracing::trace;

use crate::common::{
    config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, Spec, StoreFn},
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
                if let AdditionalConfig::FileStoreConfig { db_dir } = c.clone() {
                    // TODO: Have new function return result instead?
                    match FileStore::new(db_dir) {
                        Ok(db) => Some(db),
                        Err(e) => {
                            tracing::error!(error = %e, "Failed initializing database.");
                            None
                        }
                    }
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

        let encrypted_data = KeyDataEncrypted {
            id: data.id.clone(),
            secret_data: invert(
                data.secret_data
                    .map(|secret| {
                        self.key_handle
                            .as_ref()
                            .and_then(|key| {
                                let (v, iv) = match key.encrypt_data(&secret) {
                                    Ok(v) => v,
                                    Err(e) => return Some(Err(e)),
                                };
                                Some(Ok(StorageField::Encryped { data: v, iv }))
                            })
                            .or_else(|| Some(Ok(StorageField::Raw(secret))))
                    })
                    .flatten(),
            )?,
            public_data: data.public_data,
            additional_data: data.additional_data,
            spec: data.spec,
        };

        // choose storage Strategy
        match self {
            &StorageManager {
                key_handle: _,
                db_store: Some(ref db_store),
                kv_store: _,
                ref scope,
            } => db_store.store(scope.clone(), id, encrypted_data),
            &StorageManager {
                key_handle: _,
                db_store: _,
                kv_store: Some(ref kv_store),
                ref scope,
            } => kv_store.store(scope.clone(), id, encrypted_data),
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
                let decrypted = KeyData {
                    id: v.id.clone(),
                    secret_data: invert(
                        v.secret_data
                            .map(|secret| {
                                self.key_handle.as_ref().and_then(|key| match secret {
                                    StorageField::Encryped { data, iv } => {
                                        match key.decrypt_data(&data, &iv) {
                                            Ok(v) => Some(Ok(v)),
                                            Err(e) => Some(Err(e)),
                                        }
                                    }
                                    StorageField::Raw(data) => Some(Ok(data)),
                                })
                            })
                            .flatten(),
                    )?,
                    public_data: v.public_data,
                    additional_data: v.additional_data,
                    spec: v.spec,
                };
                return Ok(decrypted);
            }
        }

        if self.kv_store.is_some() {
            if let Ok(v) = self
                .kv_store
                .as_ref()
                .unwrap()
                .get(self.scope.clone(), id.clone())
            {
                let decrypted = KeyData {
                    id: v.id.clone(),
                    secret_data: invert(
                        v.secret_data
                            .map(|secret| match secret {
                                StorageField::Encryped { data, iv } => self
                                    .key_handle
                                    .as_ref()
                                    .and_then(|key| match key.decrypt_data(&data, &iv) {
                                        Ok(v) => Some(Ok(v)),
                                        Err(e) => Some(Err(e)),
                                    }),
                                StorageField::Raw(data) => Some(Ok(data)),
                            })
                            .flatten(),
                    )?,
                    public_data: v.public_data,
                    additional_data: v.additional_data,
                    spec: v.spec,
                };
                return Ok(decrypted);
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

    pub fn get_all_keys(&self) -> Vec<(String, Spec)> {
        // get keys from all available storage methods
        let mut keys = Vec::new();

        self.db_store.as_ref().map(|store| {
            keys.append(&mut store.get_all_keys(self.scope.clone()));
        });

        self.kv_store.as_ref().map(|store| {
            keys.append(&mut store.get_all_keys(self.scope.clone()));
        });

        keys
    }
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, CalError> {
    serde_json::to_vec(&value).map_err(|e| CalError::other(anyhow!(e)))
}

fn deserialize<'a, R: Deserialize<'a>>(data: &'a [u8]) -> Result<R, CalError> {
    serde_json::from_slice(&data).map_err(|e| CalError::other(anyhow!(e)))
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
    fn store(
        &self,
        provider: String,
        key: String,
        value: KeyDataEncrypted,
    ) -> Result<(), CalError> {
        let value = serialize(&value)?;
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

    fn get(&self, provider: String, key: String) -> Result<KeyDataEncrypted, CalError> {
        let value = pollster::block_on((self.get_fn)(format!("{}:{}", provider, key)));
        match value {
            Some(data) => {
                let value: KeyDataEncrypted = deserialize(&data)?;
                Ok(value)
            }
            None => Err(CalError::missing_key(key, KeyType::Private)),
        }
    }

    fn delete(&self, provider: String, key: String) {
        pollster::block_on((self.delete_fn)(format!("{}:{}", provider, key)));
    }

    fn get_all_keys(&self, scope: String) -> Vec<(String, Spec)> {
        let keys = pollster::block_on((self.all_keys_fn)());
        trace!("get_all_keys_kv: {:?}", keys);
        keys.into_iter()
            .filter(|k| k.starts_with(&format!("{}:", scope.clone())))
            .map(|k| k.split(':').last().unwrap().to_owned())
            .filter_map(|k| Some(self.get(scope.clone(), k).ok()?))
            .map(|key_data_enc| (key_data_enc.id.clone(), key_data_enc.spec))
            .collect()
    }
}

fn file_store_key_id(provider: &String, key: &String) -> Vec<u8> {
    format!("{}:{}", provider, key).as_bytes().to_vec()
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct FileStore {
    db: Db,
}

impl FileStore {
    fn new(db_dir: String) -> Result<Self, CalError> {
        Ok(Self { db: open(db_dir)? })
    }

    fn store(
        &self,
        provider: String,
        key: String,
        value: KeyDataEncrypted,
    ) -> Result<(), CalError> {
        let id = file_store_key_id(&provider, &key);
        let data = serialize(&value)?;
        self.db.insert(id, data)?;
        Ok(())
    }

    fn get(&self, provider: String, key: String) -> Result<KeyDataEncrypted, CalError> {
        let id = file_store_key_id(&provider, &key);
        match self.db.get(id)? {
            Some(data) => deserialize(data.as_ref()),
            None => Err(CalError::missing_value(
                format!("Sled (db): No data found for key: {}", key),
                true,
                None,
            )),
        }
    }

    fn delete(&self, provider: String, key: String) {
        let id = file_store_key_id(&provider, &key);
        match self.db.remove(id) {
            Ok(_) => {}
            Err(e) => {
                // TODO: Change delete to return result?
                tracing::error!(error = %e, "Storage Manager: Failed deletion of data for key {}", key)
            }
        }
    }

    fn get_all_keys(&self, scope: String) -> Vec<(String, Spec)> {
        self.db
            .scan_prefix(file_store_key_id(&scope, &"".into()))
            .values()
            .filter(|result| match result {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(error = %e, "Sled (db): Failed reading entry.");
                    false
                }
            })
            .map(|result| result.unwrap())
            .map(|data| deserialize(data.as_ref()))
            .filter(|result| match result {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(error = %e, "Sled (db): Failed deserialization of metadata.");
                    false
                }
            })
            .map(|result| result.unwrap())
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeyData {
    pub(crate) id: String,
    pub(crate) secret_data: Option<Vec<u8>>,
    pub(crate) public_data: Option<Vec<u8>>,
    pub(crate) additional_data: Option<Vec<u8>>,
    pub(crate) spec: Spec,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct KeyDataEncrypted {
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

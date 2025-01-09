use std::fmt;

use serde::{Deserialize, Serialize};

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
                        get: get_fn,
                        store: store_fn,
                        delete: delete_fn,
                        all_keys: all_keys_fn,
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
            secret_data: invert(data.secret_data.and_then(|secret| {
                self.key_handle.as_ref().map(|key| {
                    let (v, iv) = match key.encrypt_data(&secret) {
                        Ok(v) => v,
                        Err(e) => return Err(e),
                    };
                    Ok(StorageField::Encryped { data: v, iv })
                })
            }))?,
            public_data: data.public_data,
            additional_data: data.additional_data,
            spec: data.spec,
        };

        // choose storage Strategy
        match *self {
            StorageManager {
                key_handle: _,
                db_store: Some(ref db_store),
                kv_store: _,
                ref scope,
            } => db_store.store(scope.clone(), id, encrypted_data),
            StorageManager {
                key_handle: _,
                db_store: _,
                kv_store: Some(ref kv_store),
                ref scope,
            } => kv_store.store(&scope.clone(), &id, &encrypted_data),
            _ => Err(CalError::failed_operation(
                "neither KV Store nor DB store were initialised".to_owned(),
                true,
                None,
            )),
        }
    }

    pub(crate) fn get(&self, id: &str) -> Result<KeyData, CalError> {
        // try all available storage methods
        if self.db_store.is_some() {
            if let Ok(v) = self
                .db_store
                .as_ref()
                .unwrap()
                .get(self.scope.clone(), id.to_owned())
            {
                let decrypted = KeyData {
                    id: v.id.clone(),
                    secret_data: invert(v.secret_data.and_then(|secret| {
                        self.key_handle.as_ref().map(|key| match secret {
                            StorageField::Encryped { data, iv } => {
                                match key.decrypt_data(&data, &iv) {
                                    Ok(v) => Ok(v),
                                    Err(e) => Err(e),
                                }
                            }
                            StorageField::Raw(data) => Ok(data),
                        })
                    }))?,
                    public_data: v.public_data,
                    additional_data: v.additional_data,
                    spec: v.spec,
                };
                return Ok(decrypted);
            }
        }

        if self.kv_store.is_some() {
            if let Ok(v) = self.kv_store.as_ref().unwrap().get(&self.scope, id) {
                let decrypted = KeyData {
                    id: v.id.clone(),
                    secret_data: invert(v.secret_data.and_then(|secret| {
                        self.key_handle.as_ref().map(|key| match secret {
                            StorageField::Encryped { data, iv } => {
                                match key.decrypt_data(&data, &iv) {
                                    Ok(v) => Ok(v),
                                    Err(e) => Err(e),
                                }
                            }
                            StorageField::Raw(data) => Ok(data),
                        })
                    }))?,
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

    pub(crate) fn delete(&self, id: &str) {
        // try all available storage methods
        if self.db_store.is_some() {
            self.db_store
                .as_ref()
                .unwrap()
                .delete(self.scope.clone(), id.to_owned());
        }

        if self.kv_store.is_some() {
            self.kv_store.as_ref().unwrap().delete(&self.scope, id);
        }
    }

    pub fn get_all_keys(&self) -> Vec<Spec> {
        // get keys from all available storage methods
        let mut keys = Vec::new();

        if let Some(store) = self.db_store.as_ref() {
            keys.append(&mut store.get_all_keys(self.scope.clone()));
        }

        if let Some(store) = self.kv_store.as_ref() {
            keys.append(&mut store.get_all_keys(&self.scope));
        }

        keys
    }
}

#[derive(Clone)]
struct KVStore {
    get: GetFn,
    store: StoreFn,
    delete: DeleteFn,
    all_keys: AllKeysFn,
}

impl fmt::Debug for KVStore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KVStore {{}}")
    }
}

impl KVStore {
    fn store(&self, provider: &str, key: &str, value: &KeyDataEncrypted) -> Result<(), CalError> {
        let value = serde_json::to_vec(value).unwrap();
        let valid = pollster::block_on((self.store)(format!("{provider}:{key}"), value));
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

    fn get(&self, provider: &str, key: &str) -> Result<KeyDataEncrypted, CalError> {
        let value = pollster::block_on((self.get)(format!("{provider}:{key}")));
        match value {
            Some(data) => {
                let value: KeyDataEncrypted = serde_json::from_slice(&data).unwrap();
                Ok(value)
            }
            None => Err(CalError::missing_key(key.to_owned(), KeyType::Private)),
        }
    }

    fn delete(&self, provider: &str, key: &str) {
        pollster::block_on((self.delete)(format!("{provider}:{key}")));
    }

    fn get_all_keys(&self, scope: &str) -> Vec<Spec> {
        let keys = pollster::block_on((self.all_keys)());
        keys.into_iter()
            .filter(|k| k.starts_with(&format!("{scope}:")))
            .filter_map(|k| {
                let spec = pollster::block_on((self.get)(k))?;
                serde_json::from_slice(&spec).ok()
            })
            .collect()
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
    fn store(
        &self,
        _provider: String,
        _key: String,
        _value: KeyDataEncrypted,
    ) -> Result<(), CalError> {
        todo!()
    }

    fn get(&self, _provider: String, _key: String) -> Result<KeyDataEncrypted, CalError> {
        // TODO: implement
        Err(CalError::not_implemented())
    }

    fn delete(&self, _provider: String, _key: String) {
        // TODO: implement
    }

    fn get_all_keys(&self, _scope: String) -> Vec<Spec> {
        // TODO: implement
        Vec::new()
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

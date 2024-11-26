use serde::{Deserialize, Serialize};

use crate::common::{
    config::{AllKeysFn, DeleteFn, GetFn, KeyPairSpec, KeySpec, StoreFn},
    error::{CalError, KeyType},
    KeyHandle, Provider,
};

struct StorageManager {
    key_handle: Option<KeyHandle>,
    db_store: Option<FileStore>,
    kv_store: Option<KVStore>,
}

struct KVStore {
    get_fn: GetFn,
    store_fn: StoreFn,
    delete_fn: DeleteFn,
    all_keys_fn: AllKeysFn,
}

impl KVStore {
    fn store(&self, provider: String, key: String, value: StorageField) -> Result<(), CalError> {
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

    fn get(&self, provider: String, key: String) -> Result<StorageField, CalError> {
        let value = pollster::block_on((self.get_fn)(format!("{}:{}", provider, key)));
        match value {
            Some(data) => {
                let value: StorageField = serde_json::from_slice(&data).unwrap();
                Ok(value)
            }
            None => Err(CalError::missing_key(key, KeyType::Private)),
        }
    }

    fn delete(&self, provider: String, key: String) {
        pollster::block_on((self.delete_fn)(format!("{}:{}", provider, key)));
    }
}

struct FileStore {
    metadata_db_path: String,
    secure_db_path: String,
    pass: Vec<u8>,
}

impl FileStore {
    fn store(&self, provider: String, key: String, value: StorageField) -> Result<(), CalError> {
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
}

#[derive(Serialize, Deserialize)]
enum Spec {
    KeySpec(KeySpec),
    KeyPairSpec(KeyPairSpec),
}

#[derive(Serialize, Deserialize)]
struct KeyData {
    id: String,
    secret_data: Option<Vec<u8>>,
    public_data: Option<Vec<u8>>,
    additional_data: Option<Vec<u8>>,
    spec: Spec,
}

#[derive(Serialize, Deserialize)]
enum StorageField {
    Encryped { data: Vec<u8>, iv: Vec<u8> },
    Raw(Vec<u8>),
}

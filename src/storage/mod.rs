use std::fmt;

use hmac::Mac;
use serde::{Deserialize, Serialize};
use tracing::trace;

use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use crate::common::{
    config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, Spec, StoreFn},
    error::{CalError, KeyType},
    KeyHandle, KeyPairHandle,
};

#[derive(Clone, Debug)]
enum Storage {
    KVStore(KVStore),
    FileStore(FileStore),
}

#[derive(Clone, Debug)]
enum ChecksumProvider {
    KeyPairHandle(Box<KeyPairHandle>),
    HMAC(String),
}

#[derive(Clone, Debug)]
pub(crate) struct StorageManager {
    checksum_provider: ChecksumProvider,
    key_handle: Option<Box<KeyHandle>>,
    storage: Storage,
    scope: String,
}

fn extract_storage_method(config: &[AdditionalConfig]) -> Result<Storage, CalError> {
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

    match (db_store, kv_store) {
        (Some(db_store), None) => Ok(Storage::FileStore(db_store)),
        (None, Some(kv_store)) => Ok(Storage::KVStore(kv_store)),
        (None, None) => Err(CalError::failed_operation(
            "neither KV Store nor DB store were initialised".to_owned(),
            true,
            None,
        )),
        _ => Err(CalError::failed_operation(
            "both KV Store and DB store were initialised".to_owned(),
            true,
            None,
        )),
    }
}

fn extract_security_method(config: &[AdditionalConfig]) -> Result<ChecksumProvider, CalError> {
    let key_pair_handle = config.iter().find_map(|c| match c {
        AdditionalConfig::StorageConfigDSA(key_handle) => Some(key_handle.clone()),
        _ => None,
    });
    let hmac_pass = config.iter().find_map(|c| match c {
        AdditionalConfig::StorageConfigPass(pass) => Some(pass.clone()),
        _ => None,
    });

    match (key_pair_handle, hmac_pass) {
        (Some(key_pair_handle), None) => Ok(ChecksumProvider::KeyPairHandle(Box::new(key_pair_handle))),
        (None, Some(hmac_pass)) => Ok(ChecksumProvider::HMAC(hmac_pass)),
        _ => Err(CalError::failed_operation(
            "exactly one of AdditionalConfig::KeyHandle, AdditionalConfig::KeyPairHandle and AdditionalConfig::HMAC".to_owned(),
            true,
            None,
        )),
    }
}

impl StorageManager {
    pub(crate) fn new(scope: String, config: &[AdditionalConfig]) -> Self {
        let storage = extract_storage_method(config).expect("Failed to extract storage method");
        let key_handle = config.iter().find_map(|c| match c {
            AdditionalConfig::StorageConfigHMAC(key_handle) => Some(key_handle.clone()),
            _ => None,
        });
        let checksum_provider =
            extract_security_method(config).expect("Failed to extract security method");

        StorageManager {
            checksum_provider,
            key_handle: key_handle.map(Box::new),
            storage,
            scope,
        }
    }

    pub(crate) fn store(&self, id: String, data: KeyData) -> Result<(), CalError> {
        // encrypt secret data if KeyHandle is available

        let encrypted_data = KeyDataEncrypted {
            id: data.id.clone(),
            secret_data: data
                .secret_data
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
                        .unwrap_or(Ok(StorageField::Raw(secret)))
                })
                .transpose()?,
            public_data: data.public_data,
            additional_data: data.additional_data,
            spec: data.spec,
        };

        let encoded = serde_json::to_vec(&encrypted_data)
            .expect("Failed to encode key data, this should never happen");

        // generate checksum
        let (checksum, ctype) = match self.checksum_provider {
            ChecksumProvider::KeyPairHandle(ref key_pair_handle) => {
                let checksum = key_pair_handle.sign_data(&encoded)?;
                (checksum, ChecksumType::DSA)
            }
            ChecksumProvider::HMAC(ref pass) => {
                let mut hmac =
                    HmacSha256::new_from_slice(pass.as_bytes()).expect("Failed to create HMAC");
                hmac.update(&encoded);
                let result = hmac.finalize();
                (result.into_bytes().to_vec(), ChecksumType::HMAC)
            }
        };

        let encoded = serde_json::to_vec(&WithChecksum {
            data: encoded,
            checksum,
            checksum_type: ctype,
        })
        .expect("Failed to encode key data, this should never happen");

        // choose storage Strategy
        match self.storage {
            Storage::KVStore(ref store) => store.store(self.scope.clone(), id.clone(), encoded),
            Storage::FileStore(ref store) => store.store(self.scope.clone(), id.clone(), encoded),
        }
    }

    pub(crate) fn get(&self, id: String) -> Result<KeyData, CalError> {
        let value = match self.storage {
            Storage::KVStore(ref store) => store.get(self.scope.clone(), id.clone()),
            Storage::FileStore(ref store) => store.get(self.scope.clone(), id.clone()),
        }?;

        let decoded = serde_json::from_slice::<WithChecksum>(&value).map_err(|e| {
            CalError::failed_operation(format!("Failed to decode key data: {}", e), true, None)
        })?;

        // verify checksum
        match self.checksum_provider {
            ChecksumProvider::KeyPairHandle(ref key_pair_handle) => {
                if key_pair_handle.verify_signature(&decoded.data, &decoded.checksum)? {
                    ()
                } else {
                    return Err(CalError::failed_operation(
                        "Checksum verification failed".to_owned(),
                        true,
                        None,
                    ));
                }
            }
            ChecksumProvider::HMAC(ref pass) => {
                let mut hmac =
                    HmacSha256::new_from_slice(pass.as_bytes()).expect("Failed to create HMAC");
                hmac.update(&decoded.data);
                hmac.verify_slice(&decoded.checksum).map_err(|_| {
                    CalError::failed_operation(
                        "Checksum verification failed".to_owned(),
                        true,
                        None,
                    )
                })?;
            }
        };

        let decoded = serde_json::from_slice::<KeyDataEncrypted>(&decoded.data).map_err(|e| {
            CalError::failed_operation(format!("Failed to decode key data: {}", e), true, None)
        })?;

        let decrypted = KeyData {
            id: decoded.id.clone(),
            secret_data: decoded
                .secret_data
                .map(|secret| match secret {
                    StorageField::Encryped { data, iv } => {
                        self.key_handle
                            .as_ref()
                            .map(|key| match key.decrypt_data(&data, &iv) {
                                Ok(v) => Ok(v),
                                Err(e) => Err(e),
                            })
                    }
                    StorageField::Raw(data) => Some(Ok(data)),
                })
                .flatten()
                .transpose()?,
            public_data: decoded.public_data,
            additional_data: decoded.additional_data,
            spec: decoded.spec,
        };
        Ok(decrypted)
    }

    pub(crate) fn delete(&self, id: String) {
        match self.storage {
            Storage::KVStore(ref store) => store.delete(self.scope.clone(), id.clone()),
            Storage::FileStore(ref store) => store.delete(self.scope.clone(), id.clone()),
        }
    }

    pub fn get_all_keys(&self) -> Vec<(String, Spec)> {
        // get keys from all available storage methods
        let mut keys = Vec::new();

        match self.storage {
            Storage::KVStore(ref store) => {
                keys.append(&mut store.get_all_keys(self.scope.clone()));
            }
            Storage::FileStore(ref store) => {
                keys.append(&mut store.get_all_keys(self.scope.clone()));
            }
        }

        keys.iter()
            .map(|v| {
                serde_json::from_slice::<WithChecksum>(v.as_slice())
                    .expect("Could not decode key data, this should never happen")
            })
            .map(|with_checksum| {
                serde_json::from_slice::<KeyDataEncrypted>(&with_checksum.data.as_slice())
                    .expect("Could not decode key data, this should never happen")
            })
            .map(|v| (v.id, v.spec))
            .collect()
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
    fn store(&self, scope: String, key: String, value: Vec<u8>) -> Result<(), CalError> {
        let valid = pollster::block_on((self.store_fn)(format!("{}:{}", scope, key), value));
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

    fn get(&self, scope: String, key: String) -> Result<Vec<u8>, CalError> {
        let value = pollster::block_on((self.get_fn)(format!("{}:{}", scope, key)));
        match value {
            Some(data) => Ok(data),
            None => Err(CalError::missing_key(key, KeyType::Private)),
        }
    }

    fn delete(&self, scope: String, key: String) {
        pollster::block_on((self.delete_fn)(format!("{}:{}", scope, key)));
    }

    fn get_all_keys(&self, scope: String) -> Vec<Vec<u8>> {
        let keys = pollster::block_on((self.all_keys_fn)());
        trace!("get_all_keys_kv: {:?}", keys);
        keys.into_iter()
            .filter(|k| k.starts_with(&format!("{}:", scope.clone())))
            .map(|k| k.split(':').last().unwrap().to_owned())
            .filter_map(|k| Some(self.get(scope.clone(), k).ok()?))
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
    fn store(&self, _scope: String, _key: String, _value: Vec<u8>) -> Result<(), CalError> {
        todo!()
    }

    fn get(&self, _scope: String, _key: String) -> Result<Vec<u8>, CalError> {
        // TODO: implement
        Err(CalError::not_implemented())
    }

    fn delete(&self, _scope: String, _key: String) {
        // TODO: implement
    }

    fn get_all_keys(&self, _scope: String) -> Vec<Vec<u8>> {
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

#[derive(Serialize, Deserialize, Clone, Copy)]
pub enum ChecksumType {
    HMAC,
    DSA,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WithChecksum {
    data: Vec<u8>,
    checksum: Vec<u8>,
    checksum_type: ChecksumType,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum StorageField {
    Encryped { data: Vec<u8>, iv: Vec<u8> },
    Raw(Vec<u8>),
}

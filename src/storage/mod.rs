#![allow(clippy::upper_case_acronyms)]
use std::{fmt, path::Path};

use hmac::Mac;
use serde::{Deserialize, Serialize};
use sled::{open, Db};
use tracing::trace;

use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use crate::common::{
    config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, Spec, StoreFn},
    error::{CalError, KeyType},
    KeyHandle, KeyPairHandle,
};

mod storage_backend;

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

fn extract_storage_method(config: &[AdditionalConfig]) -> Result<Option<Storage>, CalError> {
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

    match (db_store, kv_store) {
        (Some(db_store), None) => Ok(Some(Storage::FileStore(db_store))),
        (None, Some(kv_store)) => Ok(Some(Storage::KVStore(kv_store))),
        (None, None) => Ok(None),
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
    pub(crate) fn new(
        scope: impl Into<String>,
        config: &[AdditionalConfig],
    ) -> Result<Option<Self>, CalError> {
        let storage = extract_storage_method(config)?;
        let checksum_provider = extract_security_method(config)?;
        Ok(storage.map(|storage| {
            let key_handle = config.iter().find_map(|c| match c {
                AdditionalConfig::StorageConfigHMAC(key_handle) => Some(key_handle.clone()),
                _ => None,
            });

            StorageManager {
                checksum_provider,
                key_handle: key_handle.map(Box::new),
                storage,
                scope: scope.into(),
            }
        }))
    }

    pub(crate) fn store(&self, id: impl AsRef<str>, data: KeyData) -> Result<(), CalError> {
        // encrypt secret data if KeyHandle is available

        let encrypted_data = KeyDataEncrypted {
            id: data.id.clone(),
            secret_data: data
                .secret_data
                .map(|secret| {
                    self.key_handle
                        .as_ref()
                        .map(|key| {
                            let (v, iv) = match key.encrypt(&secret) {
                                Ok(v) => v,
                                Err(e) => return Err(e),
                            };
                            Ok(StorageField::Encrypted { data: v, iv })
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
            Storage::KVStore(ref store) => store.store(self.scope.clone(), id.as_ref(), encoded),
            Storage::FileStore(ref store) => store.store(self.scope.clone(), id.as_ref(), encoded),
        }
    }

    pub(crate) fn get(&self, id: impl AsRef<str>) -> Result<KeyData, CalError> {
        let value = match self.storage {
            Storage::KVStore(ref store) => store.get(self.scope.clone(), id.as_ref()),
            Storage::FileStore(ref store) => store.get(self.scope.clone(), id.as_ref()),
        }?;

        let decoded = serde_json::from_slice::<WithChecksum>(&value).map_err(|e| {
            CalError::failed_operation(format!("Failed to decode key data: {}", e), true, None)
        })?;

        // verify checksum
        match self.checksum_provider {
            ChecksumProvider::KeyPairHandle(ref key_pair_handle) => {
                if key_pair_handle.verify_signature(&decoded.data, &decoded.checksum)? {
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
                .and_then(|secret| match secret {
                    StorageField::Encrypted { data, iv } => {
                        self.key_handle
                            .as_ref()
                            .map(|key| match key.decrypt_data(&data, &iv) {
                                Ok(v) => Ok(v),
                                Err(e) => Err(e),
                            })
                    }
                    StorageField::Raw(data) => Some(Ok(data)),
                })
                .transpose()?,
            public_data: decoded.public_data,
            additional_data: decoded.additional_data,
            spec: decoded.spec,
        };
        Ok(decrypted)
    }

    pub(crate) fn delete(&self, id: impl AsRef<str>) {
        match self.storage {
            Storage::KVStore(ref store) => store.delete(self.scope.clone(), id),
            Storage::FileStore(ref store) => store.delete(self.scope.clone(), id),
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
                serde_json::from_slice::<KeyDataEncrypted>(with_checksum.data.as_slice())
                    .expect("Could not decode key data, this should never happen")
            })
            .map(|v| (v.id, v.spec))
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
    Encrypted { data: Vec<u8>, iv: Vec<u8> },
    Raw(Vec<u8>),
}

#![allow(clippy::upper_case_acronyms)]
use std::{fmt, path::Path};

use error_stack::{ensure, report, Result, ResultExt};
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sled::{open, Db};
use thiserror::Error;
use tracing::trace;

use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use crate::common::{
    config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, Spec, StoreFn},
    error::{CId, CPath},
    KeyHandle, KeyPairHandle,
};

#[derive(Debug, Clone, Copy, Error)]
pub enum StorageManagerError {
    #[error("Error during kv store operation.")]
    KvStore,
    #[error("Error during file store operation.")]
    FileStore,
    #[error("Multiple additional configs for backend initialization provided, while only one is accepted.")]
    MultipleConfigForBackendInitialization,
    #[error("Missing configs to initialize storage backends.")]
    MissingConfigForStorageBackend,
    #[error("Multiple security configs where provided, while only one is accepted.")]
    MultipleSecurityConfigs,
    #[error("No security configs where provided.")]
    NoSecurityConfigs,
    #[error("Error during encryption.")]
    EncryptError,
    #[error("Error during decryption.")]
    DecryptError,
    #[error("Failed to sign metadata and payload.")]
    FailedSigning,
    #[error("Failed to validate metadata and payload.")]
    FailedValidation,
    #[error("Failed to serialize payload.")]
    FailedSerialization,
    #[error("Failed to deserialize payload.")]
    FailedDeserialization,
    #[error("Failed to store payload with backend.")]
    FailedToStoreWithBackend,
    #[error("Failed to get payload with backend.")]
    FailedToGetWithBackend,
}

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

fn extract_storage_method(config: &[AdditionalConfig]) -> Result<Storage, StorageManagerError> {
    let config: Vec<&AdditionalConfig> = config
        .iter()
        .filter(|e| {
            matches!(
                e,
                AdditionalConfig::FileStoreConfig { .. } | AdditionalConfig::KVStoreConfig { .. }
            )
        })
        .collect();

    ensure!(
        config.len() > 0,
        StorageManagerError::MissingConfigForStorageBackend
    );
    ensure!(
        config.len() < 2,
        StorageManagerError::MultipleConfigForBackendInitialization
    );

    Ok(match config[0] {
        AdditionalConfig::FileStoreConfig { db_dir } => Storage::FileStore(
            FileStore::new(db_dir).change_context(StorageManagerError::FileStore)?,
        ),
        AdditionalConfig::KVStoreConfig {
            get_fn,
            store_fn,
            delete_fn,
            all_keys_fn,
        } => Storage::KVStore(KVStore {
            get_fn: get_fn.clone(),
            store_fn: store_fn.clone(),
            delete_fn: delete_fn.clone(),
            all_keys_fn: all_keys_fn.clone(),
        }),
        _ => unreachable!(),
    })
}

fn extract_security_method(
    config: &[AdditionalConfig],
) -> Result<ChecksumProvider, StorageManagerError> {
    let key_pair_handle = config.iter().find_map(|c| match c {
        AdditionalConfig::StorageConfigDSA(key_handle) => Some(key_handle.clone()),
        _ => None,
    });
    let hmac_pass = config.iter().find_map(|c| match c {
        AdditionalConfig::StorageConfigPass(pass) => Some(pass.clone()),
        _ => None,
    });

    match (key_pair_handle, hmac_pass) {
        (Some(key_pair_handle), None) => {
            Ok(ChecksumProvider::KeyPairHandle(Box::new(key_pair_handle)))
        }
        (None, Some(hmac_pass)) => Ok(ChecksumProvider::HMAC(hmac_pass)),
        (None, None) => Err(report!(StorageManagerError::NoSecurityConfigs)),
        (Some(_), Some(_)) => Err(report!(StorageManagerError::MultipleSecurityConfigs)),
    }
}

impl StorageManager {
    pub(crate) fn new(
        scope: impl Into<String>,
        config: &[AdditionalConfig],
    ) -> Result<Option<Self>, StorageManagerError> {
        let storage = match extract_storage_method(config) {
            Ok(s) => s,
            Err(e)
                if matches!(
                    e.current_context(),
                    StorageManagerError::MissingConfigForStorageBackend
                ) =>
            {
                return Ok(None);
            }
            Err(e) => {
                return Err(e);
            }
        };

        let checksum_provider = extract_security_method(config)?;

        let key_handle = config.iter().find_map(|c| match c {
            AdditionalConfig::StorageConfigHMAC(key_handle) => Some(key_handle.clone()),
            _ => None,
        });

        Ok(Some(StorageManager {
            checksum_provider,
            key_handle: key_handle.map(Box::new),
            storage,
            scope: scope.into(),
        }))
    }

    pub(crate) fn store(
        &self,
        id: impl AsRef<str>,
        data: KeyData,
    ) -> Result<(), StorageManagerError> {
        // encrypt secret data if KeyHandle is available

        let encrypted_data = KeyDataEncrypted {
            id: data.id.clone(),
            secret_data: data
                .secret_data
                .map(|secret| {
                    self.key_handle
                        .as_ref()
                        .map(|key| {
                            let (v, iv) = key
                                .encrypt(&secret)
                                .change_context(StorageManagerError::EncryptError)?;
                            Result::<StorageField, _>::Ok(StorageField::Encrypted { data: v, iv })
                        })
                        .unwrap_or(Ok(StorageField::Raw(secret)))
                })
                .transpose()?,
            public_data: data.public_data,
            additional_data: data.additional_data,
            spec: data.spec,
        };

        let encoded = serde_json::to_vec(&encrypted_data)
            .change_context(StorageManagerError::FailedSerialization)?;

        // generate checksum
        let (checksum, ctype) = match self.checksum_provider {
            ChecksumProvider::KeyPairHandle(ref key_pair_handle) => {
                let checksum = key_pair_handle
                    .sign_data(&encoded)
                    .change_context(StorageManagerError::FailedSigning)?;
                (checksum, ChecksumType::DSA)
            }
            ChecksumProvider::HMAC(ref pass) => {
                let mut hmac = HmacSha256::new_from_slice(pass.as_bytes())
                    .change_context(StorageManagerError::FailedSigning)?;
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
        .change_context(StorageManagerError::FailedDeserialization)?;

        // choose storage Strategy
        match self.storage {
            Storage::KVStore(ref store) => store
                .store(self.scope.clone(), id.as_ref(), encoded)
                .change_context(StorageManagerError::FailedToStoreWithBackend),
            Storage::FileStore(ref store) => store
                .store(self.scope.clone(), id.as_ref(), encoded)
                .change_context(StorageManagerError::FailedToStoreWithBackend),
        }
    }

    pub(crate) fn get(&self, id: impl AsRef<str>) -> Result<KeyData, StorageManagerError> {
        let value = match self.storage {
            Storage::KVStore(ref store) => store
                .get(self.scope.clone(), id.as_ref())
                .change_context(StorageManagerError::KvStore),
            Storage::FileStore(ref store) => store
                .get(self.scope.clone(), id.as_ref())
                .change_context(StorageManagerError::FileStore),
        }?;

        let decoded = serde_json::from_slice::<WithChecksum>(&value)
            .change_context(StorageManagerError::FailedDeserialization)?;

        // verify checksum
        match self.checksum_provider {
            ChecksumProvider::KeyPairHandle(ref key_pair_handle) => {
                if key_pair_handle
                    .verify_signature(&decoded.data, &decoded.checksum)
                    .change_context(StorageManagerError::FailedValidation)?
                {
                } else {
                    return Err(report!(StorageManagerError::FailedValidation));
                }
            }
            ChecksumProvider::HMAC(ref pass) => {
                let mut hmac = HmacSha256::new_from_slice(pass.as_bytes())
                    .change_context(StorageManagerError::FailedValidation)?;
                hmac.update(&decoded.data);
                hmac.verify_slice(&decoded.checksum)
                    .change_context(StorageManagerError::FailedValidation)?;
            }
        };

        let decoded = serde_json::from_slice::<KeyDataEncrypted>(&decoded.data)
            .change_context(StorageManagerError::FailedDeserialization)?;

        let decrypted = KeyData {
            id: decoded.id.clone(),
            secret_data: decoded
                .secret_data
                .and_then(|secret| match secret {
                    StorageField::Encrypted { data, iv } => self.key_handle.as_ref().map(|key| {
                        key.decrypt_data(&data, &iv)
                            .change_context(StorageManagerError::DecryptError)
                    }),
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

    pub fn get_all_keys(&self) -> Vec<Result<(String, Spec), StorageManagerError>> {
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
                    .change_context(StorageManagerError::FailedDeserialization)
                    .attach_printable("Could not decode data blob.")
            })
            .map(|result| {
                result.map(|with_checksum| {
                    serde_json::from_slice::<KeyDataEncrypted>(with_checksum.data.as_slice())
                        .change_context(StorageManagerError::FailedDeserialization)
                        .attach_printable("Could not decode key data.")
                })
            })
            .flatten()
            .map(|result| result.map(|v| (v.id, v.spec)))
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

#[derive(Debug, Clone, Copy, Error)]
pub enum KVStoreError {
    #[error("Failed to store key, the handle may still be valid")]
    StoringFailed,
    #[error("failed to find key")]
    MissingKey,
}

impl KVStore {
    fn store(
        &self,
        scope: impl AsRef<str>,
        key: impl AsRef<str>,
        value: Vec<u8>,
    ) -> Result<(), KVStoreError> {
        let valid = pollster::block_on((self.store_fn)(
            format!("{}:{}", scope.as_ref(), key.as_ref()),
            value,
        ));
        if valid {
            Ok(())
        } else {
            Err(report!(KVStoreError::StoringFailed))
        }
    }

    fn get(&self, scope: impl AsRef<str>, key: impl AsRef<str>) -> Result<Vec<u8>, KVStoreError> {
        let value = pollster::block_on((self.get_fn)(format!(
            "{}:{}",
            scope.as_ref(),
            key.as_ref()
        )));
        match value {
            Some(data) => Ok(data),
            None => Err(report!(KVStoreError::MissingKey).attach_printable(CId::from(key))),
        }
    }

    fn delete(&self, scope: impl AsRef<str>, key: impl AsRef<str>) {
        pollster::block_on((self.delete_fn)(format!(
            "{}:{}",
            scope.as_ref(),
            key.as_ref()
        )));
    }

    fn get_all_keys(&self, scope: String) -> Vec<Vec<u8>> {
        let keys = pollster::block_on((self.all_keys_fn)());
        trace!("get_all_keys_kv: {:?}", keys);
        keys.into_iter()
            .filter(|k| k.starts_with(&format!("{}:", scope.clone())))
            .map(|k| k.split(':').last().unwrap().to_owned())
            .filter_map(|k| self.get(scope.clone(), k).ok())
            .collect()
    }
}

fn file_store_key_id(provider: impl AsRef<str>, key: impl AsRef<str>) -> Vec<u8> {
    format!("{}:{}", provider.as_ref(), key.as_ref())
        .as_bytes()
        .to_vec()
}

#[derive(Debug, Clone, Copy, Error)]
pub enum FileStoreError {
    #[error("Failed to open database.")]
    FailedToOpenDb,
    #[error("Failed to insert element into database.")]
    FailedInsert,
    #[error("Failed to get an element into database.")]
    FailedGet,
    #[error("Requested value is missing in db.")]
    MissingValue,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
struct FileStore {
    db: Db,
}

impl FileStore {
    fn new(db_dir: impl AsRef<Path>) -> Result<Self, FileStoreError> {
        Ok(Self {
            db: open(&db_dir)
                .change_context(FileStoreError::FailedToOpenDb)
                .attach_printable_lazy(|| CPath::from(db_dir.as_ref()))?,
        })
    }

    fn store(
        &self,
        provider: impl AsRef<str>,
        key: impl AsRef<str>,
        value: Vec<u8>,
    ) -> Result<(), FileStoreError> {
        let id = file_store_key_id(provider, &key);
        self.db
            .insert(id, value)
            .change_context(FileStoreError::FailedInsert)
            .attach_printable_lazy(|| CId::from(&key))?;
        Ok(())
    }

    fn get(
        &self,
        provider: impl AsRef<str>,
        key: impl AsRef<str>,
    ) -> Result<Vec<u8>, FileStoreError> {
        let id = file_store_key_id(provider, key.as_ref());
        match self.db.get(id).change_context(FileStoreError::FailedGet)? {
            Some(data) => Ok(data.as_ref().to_vec()),
            None => Err(report!(FileStoreError::MissingValue).attach_printable(CId::from(&key))),
        }
    }

    fn delete(&self, provider: impl AsRef<str>, key: impl AsRef<str>) {
        let id = file_store_key_id(provider, key.as_ref());
        match self.db.remove(id) {
            Ok(_) => {}
            Err(e) => {
                // TODO: Change delete to return result?
                tracing::error!(error = %e, "Storage Manager: Failed deletion of data for key {}", key.as_ref())
            }
        }
    }

    fn get_all_keys(&self, scope: impl AsRef<str>) -> Vec<Vec<u8>> {
        self.db
            .scan_prefix(file_store_key_id(scope, ""))
            .values()
            .filter(|result| match result {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(error = %e, "Sled (db): Failed reading entry.");
                    false
                }
            })
            .map(|result| result.unwrap().as_ref().to_vec())
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

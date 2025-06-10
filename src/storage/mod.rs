#![allow(clippy::upper_case_acronyms)]
use std::{cell::Cell, fmt, path::Path, sync::Arc};

use anyhow::anyhow;
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sled::{open, Db};
use storage_backend::StorageBackend;
use thiserror::Error;
use tracing::trace;

use hmac::Hmac;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use crate::{
    common::{
        config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, Spec, StoreFn},
        error::{CalError, KeyType},
        KeyHandle, KeyPairHandle,
    },
    storage::{
        encryption::EncryptionBackendExplicit, signature::SignatureBackendExplicit,
        storage_backend::StorageBackendExplicit,
    },
};

mod encryption;
mod key;
mod signature;
mod storage_backend;

#[derive(Debug, Clone, Copy, Error)]
pub enum StorageManagerError {
    #[error("Some options in the given provider implementation config are in conflict with each other: {description}")]
    ConflictingProviderImplConfig { description: &'static str },
}

#[derive(Clone, Debug)]
pub(crate) struct StorageManager {
    signature: SignatureBackendExplicit,
    encryption: EncryptionBackendExplicit,
    storage: StorageBackendExplicit,
    scope: String,
}

fn extract_storage_method(
    config: &[AdditionalConfig],
) -> Result<impl StorageBackend, StorageManagerError> {
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
                (checksum, Signature::DSA)
            }
            ChecksumProvider::HMAC(ref pass) => {
                let mut hmac = HmacSha256::new_from_slice(pass.as_bytes())
                    .change_context(StorageManagerError::FailedSigning)?;
                hmac.update(&encoded);
                let result = hmac.finalize();
                (result.into_bytes().to_vec(), Signature::HMAC)
            }
        };

        let encoded = serde_json::to_vec(&SignedData {
            data: encoded,
            checksum,
            signature: ctype,
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

        let decoded = serde_json::from_slice::<SignedData>(&value)
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
                serde_json::from_slice::<SignedData>(v.as_slice())
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
pub(crate) enum Signature {
    HMAC(Vec<u8>),
    DSA(Vec<u8>),
    None,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct SignedData {
    data: Vec<u8>,
    signature: Signature,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum StorageField {
    Encrypted { data: Vec<u8>, iv: Vec<u8> },
    EncryptedAsymmetric { data: Vec<u8> },
    Raw(Vec<u8>),
}

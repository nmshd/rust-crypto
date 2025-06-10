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
        error::{self, CalError, KeyType},
        KeyHandle, KeyPairHandle,
    },
    storage::{
        encryption::{EncryptionBackend, EncryptionBackendError, EncryptionBackendExplicit},
        signature::{SignatureBackend, SignatureBackendError, SignatureBackendExplicit},
        storage_backend::{StorageBackendError, StorageBackendExplicit},
    },
};

mod encryption;
mod key;
mod signature;
mod storage_backend;

#[derive(Debug, Error)]
pub enum StorageManagerError {
    #[error("Some options in the given provider implementation config are in conflict with each other: {description}")]
    ConflictingProviderImplConfig { description: &'static str },
    #[error("A needed option was not supplied: {description}")]
    MissingProviderImplConfigOption { description: &'static str },
    #[error("Failed to initialize a storage backend: {description}")]
    InitializeStorageBackend {
        source: StorageBackendError,
        description: &'static str,
    },
    #[error("Failed to encrypt sensitive data.")]
    Encrypt { source: EncryptionBackendError },
    #[error("Failed serialization of data.")]
    Serialize { source: rmp_serde::encode::Error },
    #[error("Failed to sign data.")]
    Sign { source: SignatureBackendError },
    #[error("Failed to store data.")]
    Store { source: StorageBackendError }
}

#[derive(Clone, Debug)]
pub(crate) struct StorageManager {
    signature: SignatureBackendExplicit,
    encryption: EncryptionBackendExplicit,
    storage: StorageBackendExplicit,
    scope: String,
}

impl StorageManager {
    pub(crate) fn new(
        scope: impl Into<String>,
        config: &[AdditionalConfig],
    ) -> Result<Option<Self>, StorageManagerError> {
        let storage_backend = match StorageBackendExplicit::new(config) {
            Ok(e) => e,
            Err(e)
                if matches!(
                    e,
                    StorageManagerError::MissingProviderImplConfigOption { .. }
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };

        Ok(Some(Self {
            signature: SignatureBackendExplicit::new(config)?,
            encryption: EncryptionBackendExplicit::new(config)?,
            storage: storage_backend,
            scope: scope.into(),
        }))
    }

    pub(crate) fn store(
        &self,
        id: impl AsRef<str>,
        data: KeyData,
    ) -> Result<(), StorageManagerError> {
        let key_data_encrypted = KeyDataEncrypted {
            id: data.id,
            secret_data: data
                .secret_data
                .map(|e| self.encryption.encrypt(&e))
                .transpose()
                .map_err(|e| StorageManagerError::Encrypt { source: e })?,
            public_data: data.public_data,
            additional_data: data.additional_data,
            spec: data.spec,
        };

        let key_data_encrypted_encoded = rmp_serde::to_vec(&key_data_encrypted)
            .map_err(|e| StorageManagerError::Serialize { source: e })?;

        let key_data_encrypted_encoded_signed = self
            .signature
            .sign(key_data_encrypted_encoded)
            .map_err(|e| StorageManagerError::Sign { source: e })?;

        let key_data_encrypted_encoded_signed_serialized =
            rmp_serde::to_vec(&key_data_encrypted_encoded_signed)
                .map_err(|e| StorageManagerError::Serialize { source: e })?;

            self.storage.store(id, &key_data_encrypted_encoded_signed_serialized).map_err(|e| StorageManagerError::Store { source: e })
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

#![allow(clippy::upper_case_acronyms)]
use std::{cell::Cell, fmt, path::Path, sync::Arc};

use anyhow::anyhow;
use hmac::Mac;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sled::{open, Db};
use storage_backend::StorageBackend;
use thiserror::Error;
use tracing::trace;

use hmac::Hmac;
use sha2::Sha256;
use tracing_subscriber::registry::Scope;

type HmacSha256 = Hmac<Sha256>;

use crate::{
    common::{
        config::{AdditionalConfig, AllKeysFn, DeleteFn, GetFn, Spec, StoreFn},
        error::{self, CalError, KeyType},
        KeyHandle, KeyPairHandle,
    },
    storage::{
        encryption::{EncryptionBackend, EncryptionBackendError, EncryptionBackendExplicit},
        key::{StorageManagerKey, StorageManagerKeyFactory},
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
    #[error("Failed to decrypt ciphertext.")]
    Decrypt { source: EncryptionBackendError },
    #[error("Failed serialization of data.")]
    Serialize { source: rmp_serde::encode::Error },
    #[error("Failed deserialization of data.")]
    Deserialize { source: rmp_serde::decode::Error },
    #[error("Failed to sign data.")]
    Sign { source: SignatureBackendError },
    #[error("Failed verification of data.")]
    Verify { source: SignatureBackendError },
    #[error("Failed to store data.")]
    Store { source: StorageBackendError },
    #[error("Failed to get data from storage backend.")]
    Get { source: StorageBackendError },
    #[error("Failed to delete entry.")]
    Delete { source: StorageBackendError },
    #[error("Failed to create a scope for the storage manager.")]
    Scope { source: anyhow::Error },
    #[error("Failed to get key ids.")]
    GetKeys { source: anyhow::Error },
}

#[derive(Clone, Debug)]
pub(crate) struct StorageManager {
    signature: SignatureBackendExplicit,
    encryption: EncryptionBackendExplicit,
    storage: StorageBackendExplicit,
    scope: StorageManagerKeyFactory,
}

impl StorageManager {
    pub(crate) fn new(
        scope: impl Into<String>,
        config: &[AdditionalConfig],
    ) -> Result<Option<Self>, StorageManagerError> {
        let storage = match StorageBackendExplicit::new(config) {
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

        let signature = SignatureBackendExplicit::new(config)?;
        let encryption = EncryptionBackendExplicit::new(config)?;
        let scope = StorageManagerKeyFactory {
            provider_scope: scope.into(),
            encryption_scope: encryption
                .scope()
                .map_err(|e| StorageManagerError::Scope { source: anyhow!(e) })?,
            signature_scope: signature
                .scope()
                .map_err(|e| StorageManagerError::Scope { source: anyhow!(e) })?,
        };

        Ok(Some(Self {
            signature,
            encryption,
            storage,
            scope,
        }))
    }

    pub(crate) fn store(
        &self,
        id: impl Into<String>,
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

        let scoped_id = self.scope.scoped_key(id)?;

        self.storage
            .store(scoped_id, &key_data_encrypted_encoded_signed_serialized)
            .map_err(|e| StorageManagerError::Store { source: e })
    }

    pub(crate) fn get(&self, id: impl Into<String>) -> Result<KeyData, StorageManagerError> {
        let scoped_id = self.scope.scoped_key(id)?;

        let value = self
            .storage
            .get(scoped_id)
            .map_err(|e| StorageManagerError::Get { source: e })?;

        let signed_data = rmp_serde::from_slice::<SignedData>(&value)
            .map_err(|e| StorageManagerError::Deserialize { source: e })?;

        let key_encrypted_data = rmp_serde::from_slice::<KeyDataEncrypted>(&signed_data.data)
            .map_err(|e| StorageManagerError::Deserialize { source: e })?;

        self.signature
            .verify(signed_data)
            .map_err(|e| StorageManagerError::Verify { source: e })?;

        let key_data = KeyData {
            id: key_encrypted_data.id,
            secret_data: key_encrypted_data
                .secret_data
                .map(|encrypted_data| self.encryption.decrypt(encrypted_data))
                .transpose()
                .map_err(|e| StorageManagerError::Decrypt { source: e })?,
            public_data: key_encrypted_data.public_data,
            additional_data: key_encrypted_data.additional_data,
            spec: key_encrypted_data.spec,
        };

        Ok(key_data)
    }

    pub(crate) fn delete(&self, id: impl Into<String>) -> Result<(), StorageManagerError> {
        let scoped_id = self.scope.scoped_key(id)?;

        self.storage
            .delete(scoped_id)
            .map_err(|e| StorageManagerError::Delete { source: e })
    }

    pub fn get_all_keys(&self) -> Vec<Result<(String, Spec), StorageManagerError>> {
        self.storage
            .keys()
            .map_err(|e| StorageManagerError::GetKeys { source: anyhow!(e) })?
            .into_iter()
            .map(|e| match self.storage.get(e) {
                Ok(signed_data) => //TODO
            }))
            .map(|e| StorageManagerKey::deserialize(e))
            .process_results(|iter| iter.map(|e| e.key_id))
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

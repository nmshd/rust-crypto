use itertools::Itertools;
use serde::{Deserialize, Serialize};
use storage_backend::StorageBackend;
use thiserror::Error;

use crate::{
    common::config::{AdditionalConfig, Spec},
    storage::{
        encryption::{EncryptionBackend, EncryptionBackendError, EncryptionBackendExplicit},
        key::{ScopedKey, ScopedKeyFactory},
        signature::{SignatureBackend, SignatureBackendError, SignatureBackendExplicit},
        storage_backend::{
            StorageBackendError, StorageBackendExplicit, StorageBackendInitializationError,
        },
    },
};

mod encryption;
mod key;
mod signature;
mod storage_backend;

#[derive(Debug, Error)]
pub enum StorageManagerError {
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
    #[error("Failed to get key ids.")]
    GetKeys { source: StorageBackendError },
}

#[derive(Debug, Error)]
pub enum StorageManagerInitializationError {
    #[error("Failed to get the signature backend scope for the storage manager.")]
    ScopeSignature { source: SignatureBackendError },
    #[error("Failed to get the encryption backend scope for the storage manager.")]
    ScopeEncryption { source: EncryptionBackendError },
    #[error("Some options in the given provider implementation config are in conflict with each other: {description}")]
    ConflictingProviderImplConfig { description: &'static str },
    #[error("A needed option was not supplied: {description}")]
    MissingProviderImplConfigOption { description: &'static str },
    #[error("Failed to initialize a storage backend.")]
    StorageBackendInitialization(#[from] StorageBackendInitializationError),
}

#[derive(Clone, Debug)]
pub(crate) struct StorageManager {
    signature: SignatureBackendExplicit,
    encryption: EncryptionBackendExplicit,
    storage: StorageBackendExplicit,
    scope: ScopedKeyFactory,
}

fn deserialize<'a, T: Deserialize<'a>>(value: &'a [u8]) -> Result<T, StorageManagerError> {
    rmp_serde::from_slice(value).map_err(|e| StorageManagerError::Deserialize { source: e })
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageManagerError> {
    rmp_serde::to_vec_named(value).map_err(|e| StorageManagerError::Serialize { source: e })
}

impl StorageManager {
    pub(crate) fn new(
        scope: impl Into<String>,
        config: &[AdditionalConfig],
    ) -> Result<Option<Self>, StorageManagerInitializationError> {
        let storage = match StorageBackendExplicit::new(config) {
            Ok(e) => e,
            Err(e)
                if matches!(
                    e,
                    StorageManagerInitializationError::MissingProviderImplConfigOption { .. }
                ) =>
            {
                return Ok(None)
            }
            Err(e) => return Err(e),
        };

        let signature = SignatureBackendExplicit::new(config)?;
        let encryption = EncryptionBackendExplicit::new(config)?;
        let scope = ScopedKeyFactory {
            provider_scope: scope.into(),
            encryption_scope: encryption
                .scope()
                .map_err(|e| StorageManagerInitializationError::ScopeEncryption { source: e })?,
            signature_scope: signature
                .scope()
                .map_err(|e| StorageManagerInitializationError::ScopeSignature { source: e })?,
        };

        Ok(Some(Self {
            signature,
            encryption,
            storage,
            scope,
        }))
    }

    fn encrypt_key_data(&self, key_data: KeyData) -> Result<KeyDataEncrypted, StorageManagerError> {
        let encrypted_sensitive_data = key_data
            .secret_data
            .map(|e| self.encryption.encrypt(&e))
            .transpose()
            .map_err(|e| StorageManagerError::Encrypt { source: e })?;

        Ok(KeyDataEncrypted {
            id: key_data.id,
            secret_data: encrypted_sensitive_data,
            public_data: key_data.public_data,
            additional_data: key_data.additional_data,
            spec: key_data.spec,
        })
    }

    fn decrypt_encrypted_key_data(
        &self,
        encrypted_key_data: KeyDataEncrypted,
    ) -> Result<KeyData, StorageManagerError> {
        let sensitive_data = encrypted_key_data
            .secret_data
            .map(|encrypted_data| self.encryption.decrypt(encrypted_data))
            .transpose()
            .map_err(|e| StorageManagerError::Decrypt { source: e })?;

        Ok(KeyData {
            id: encrypted_key_data.id,
            secret_data: sensitive_data,
            public_data: encrypted_key_data.public_data,
            additional_data: encrypted_key_data.additional_data,
            spec: encrypted_key_data.spec,
        })
    }

    fn sign_encrypted_key_data(
        &self,
        encrypted_key_data: KeyDataEncrypted,
    ) -> Result<SignedData, StorageManagerError> {
        let serialized_encrypted_key_data = serialize(&encrypted_key_data)?;

        self.signature
            .sign(serialized_encrypted_key_data)
            .map_err(|e| StorageManagerError::Sign { source: e })
    }

    fn verify_signed_encrypted_key_data(
        &self,
        signed_encrypted_key_data: SignedData,
    ) -> Result<KeyDataEncrypted, StorageManagerError> {
        let verified_blob = self
            .signature
            .verify(signed_encrypted_key_data)
            .map_err(|e| StorageManagerError::Verify { source: e })?;

        deserialize::<KeyDataEncrypted>(&verified_blob)
    }

    pub(crate) fn store(
        &self,
        id: impl Into<String>,
        data: KeyData,
    ) -> Result<(), StorageManagerError> {
        let key_data_encrypted = self.encrypt_key_data(data)?;

        let key_data_encrypted_encoded_signed = self.sign_encrypted_key_data(key_data_encrypted)?;

        let key_data_encrypted_encoded_signed_serialized =
            serialize(&key_data_encrypted_encoded_signed)?;

        let scoped_key = self.scope.scoped_key(id);

        self.storage
            .store(scoped_key, &key_data_encrypted_encoded_signed_serialized)
            .map_err(|e| StorageManagerError::Store { source: e })
    }

    fn get_partial(&self, scoped_key: ScopedKey) -> Result<KeyDataEncrypted, StorageManagerError> {
        let value = self
            .storage
            .get(scoped_key)
            .map_err(|e| StorageManagerError::Get { source: e })?;

        let signed_data: SignedData = deserialize(&value)?;

        self.verify_signed_encrypted_key_data(signed_data)
    }

    pub(crate) fn get(&self, id: impl Into<String>) -> Result<KeyData, StorageManagerError> {
        let scoped_key = self.scope.scoped_key(id);

        let key_encrypted_data = self.get_partial(scoped_key)?;

        self.decrypt_encrypted_key_data(key_encrypted_data)
    }

    pub(crate) fn delete(&self, id: impl Into<String>) -> Result<(), StorageManagerError> {
        let scoped_id = self.scope.scoped_key(id);

        self.storage
            .delete(scoped_id)
            .map_err(|e| StorageManagerError::Delete { source: e })
    }

    pub(crate) fn get_all_keys(&self) -> Vec<Result<(String, Spec), StorageManagerError>> {
        self.storage
            .keys()
            .into_iter()
            .map(|result| result.map_err(|err| StorageManagerError::GetKeys { source: err }))
            .filter_ok(|scoped_key| {
                scoped_key.encryption_scope == self.scope.encryption_scope
                    && scoped_key.signature_scope == self.scope.signature_scope
                    && scoped_key.provider_scope == self.scope.provider_scope
            })
            .map_ok(|scoped_key| {
                let id = scoped_key.key_id.clone();
                let key_data = self.get_partial(scoped_key)?;
                Ok::<_, StorageManagerError>((id, key_data.spec))
            })
            .flatten_ok()
            .collect()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use nanoid::nanoid;
    use rstest::{fixture, rstest};

    use crate::{prelude::KeySpec, tests::TestStore};

    use super::*;

    static TEST_KV_STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

    const DUMMY_SPEC: Spec = Spec::KeySpec(KeySpec {
        cipher: crate::prelude::Cipher::AesGcm256,
        signing_hash: crate::prelude::CryptoHash::Sha2_512,
        ephemeral: true,
        non_exportable: false,
    });

    #[test]
    fn none_on_empty_config() {
        let config = vec![];
        let storage = StorageManager::new(nanoid!(), &config).unwrap();
        assert!(storage.is_none());
    }

    #[fixture]
    fn storage_manager() -> StorageManager {
        let config = TEST_KV_STORE.impl_config().additional_config;
        StorageManager::new(nanoid!(), &config).unwrap().unwrap()
    }

    #[test]
    fn create_unencrypted_storage_manager() {
        let _storage = storage_manager();
    }

    #[fixture]
    fn key_data_empty() -> KeyData {
        KeyData {
            id: nanoid!(),
            secret_data: None,
            public_data: None,
            additional_data: None,
            spec: DUMMY_SPEC,
        }
    }

    #[fixture]
    fn key_data_no_sensitive_data() -> KeyData {
        KeyData {
            id: nanoid!(),
            secret_data: None,
            public_data: Some(nanoid::rngs::default(12)),
            additional_data: Some(nanoid::rngs::default(12)),
            spec: DUMMY_SPEC,
        }
    }

    #[fixture]
    fn key_data_filled() -> KeyData {
        KeyData {
            id: nanoid!(),
            secret_data: Some(nanoid::rngs::default(12)),
            public_data: Some(nanoid::rngs::default(12)),
            additional_data: Some(nanoid::rngs::default(12)),
            spec: DUMMY_SPEC,
        }
    }

    #[fixture]
    fn key_id() -> String {
        nanoid!()
    }

    #[rstest]
    #[case::key_data_empty(key_data_empty())]
    #[case::key_data_non_sensitive(key_data_no_sensitive_data())]
    #[case::key_data_filled(key_data_filled())]
    fn test_store(storage_manager: StorageManager, key_id: String, #[case] key_data: KeyData) {
        storage_manager.store(key_id, key_data).unwrap();
    }

    #[rstest]
    #[case::key_data_empty(key_data_empty())]
    #[case::key_data_non_sensitive(key_data_no_sensitive_data())]
    #[case::key_data_filled(key_data_filled())]
    fn test_store_and_get(
        storage_manager: StorageManager,
        key_id: String,
        #[case] key_data: KeyData,
    ) {
        storage_manager.store(&key_id, key_data.clone()).unwrap();

        let loaded_key_data = storage_manager.get(key_id).unwrap();

        assert_eq!(key_data, loaded_key_data);
    }

    #[rstest]
    #[case::key_data_empty(key_data_empty())]
    #[case::key_data_non_sensitive(key_data_no_sensitive_data())]
    #[case::key_data_filled(key_data_filled())]
    fn test_store_and_all_keys(
        storage_manager: StorageManager,
        key_id: String,
        #[case] key_data: KeyData,
    ) {
        storage_manager.store(&key_id, key_data.clone()).unwrap();

        let keys = storage_manager.get_all_keys();
        assert_eq!(keys.len(), 1);
        let (id, spec) = keys[0].as_ref().unwrap();
        assert_eq!(id, &key_id);
        assert_eq!(spec, &key_data.spec);
    }

    #[rstest]
    #[case::key_data_empty(key_data_empty())]
    #[case::key_data_non_sensitive(key_data_no_sensitive_data())]
    #[case::key_data_filled(key_data_filled())]
    fn test_store_and_delete(
        storage_manager: StorageManager,
        key_id: String,
        #[case] key_data: KeyData,
    ) {
        assert_eq!(storage_manager.get_all_keys().len(), 0);

        storage_manager.store(&key_id, key_data.clone()).unwrap();

        assert_eq!(storage_manager.get_all_keys().len(), 1);

        storage_manager.delete(key_id).unwrap();

        assert_eq!(storage_manager.get_all_keys().len(), 0);
    }
}

use std::fmt::Debug;

use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use thiserror::Error;

mod kv_store;
mod sqlite_store;

use kv_store::KvStorageBackend;

use crate::{
    prelude::AdditionalConfig,
    storage::{
        key::ScopedKey,
        storage_backend::{
            kv_store::KvStorageBackendError,
            sqlite_store::{SqliteBackend, SqliteBackendError, SqliteBackendInitializationError},
        },
        StorageManagerInitializationError,
    },
};

#[derive(Debug, Error)]
pub enum StorageBackendError {
    #[error(transparent)]
    KvStore(#[from] KvStorageBackendError),
    #[error(transparent)]
    Sqlite(#[from] SqliteBackendError),
}

#[derive(Debug, Error)]
pub enum StorageBackendInitializationError {
    #[error(transparent)]
    Sqlite(#[from] SqliteBackendInitializationError),
}

#[enum_dispatch]
pub trait StorageBackend: Debug {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError>;
    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError>;
    fn delete(&self, key: ScopedKey) -> Result<(), StorageBackendError>;
    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>>;
}

#[enum_dispatch(StorageBackend)]
#[derive(Clone)]
pub(super) enum StorageBackendExplicit {
    KvStorageBackend,
    SqliteBackend,
}

impl Debug for StorageBackendExplicit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageBackendExplicit::KvStorageBackend(_) => {
                f.debug_struct("KvStorageBackend").finish()
            }
            StorageBackendExplicit::SqliteBackend(_) => writeln!(f, "SqliteBackend"),
        }
    }
}

impl StorageBackendExplicit {
    pub fn new(config: &[AdditionalConfig]) -> Result<Self, StorageManagerInitializationError> {
        let storage_backend_option_from_additional_config =
            |additional_data: &AdditionalConfig| match additional_data {
                AdditionalConfig::FileStoreConfig { db_dir } => {
                    Some(SqliteBackend::new(db_dir).map(Self::from))
                }
                AdditionalConfig::KVStoreConfig {
                    get_fn,
                    store_fn,
                    delete_fn,
                    all_keys_fn,
                } => Some(Ok(Self::from(KvStorageBackend {
                    get_fn: get_fn.clone(),
                    store_fn: store_fn.clone(),
                    delete_fn: delete_fn.clone(),
                    all_keys_fn: all_keys_fn.clone(),
                }))),
                _ => None,
            };

        // `count` is either `0` or `2..`.
        let error_from_count = |count: usize| {
            if count > 1 {
                StorageManagerInitializationError::ConflictingProviderImplConfig {
                    description: "Expected either FileStoreConfig OR KVStoreConfig, not both.",
                }
            } else {
                StorageManagerInitializationError::MissingProviderImplConfigOption {
                    description:
                        "No additional config for initializing a storage backend was given.",
                }
            }
        };

        config
            .iter()
            .filter_map(storage_backend_option_from_additional_config)
            .map(|result| result.map_err(StorageManagerInitializationError::from))
            .exactly_one()
            .map_err(|iter| error_from_count(iter.count()))?
    }
}

#[cfg(test)]
mod test {
    // cargo test uses multiple processes for executing tests.
    // This results in the global db map being ineffective for unit tests.

    use crate::tests::TestStore;
    use rstest::rstest;
    use std::sync::LazyLock;
    use tempfile::{tempdir_in, TempDir};

    use super::*;

    use nanoid::nanoid;

    static TEST_KV_STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

    const TARGET_FOLDER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");

    static TEST_TMP_DIR: LazyLock<TempDir> = LazyLock::new(|| tempdir_in(TARGET_FOLDER).unwrap());

    fn random_scoped_key() -> ScopedKey {
        ScopedKey {
            key_id: nanoid!(),
            provider_scope: nanoid!(),
            encryption_scope: nanoid!(),
            signature_scope: nanoid!(),
        }
    }

    fn create_kv_storage_backend() -> StorageBackendExplicit {
        let config = TEST_KV_STORE.impl_config();
        StorageBackendExplicit::new(&config.additional_config).unwrap()
    }

    fn create_file_storage_backend() -> StorageBackendExplicit {
        let mut db_dir = TEST_TMP_DIR.path().to_path_buf();
        db_dir.push(&nanoid!());
        let additional_configs = vec![AdditionalConfig::FileStoreConfig {
            db_dir: db_dir.to_string_lossy().to_string(),
        }];
        StorageBackendExplicit::new(&additional_configs).unwrap()
    }

    #[rstest]
    fn test_create_valid_storage_backend(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let _ = create();
    }

    #[rstest]
    fn test_invalid_creation_missing_config() {
        let additional_config = vec![];
        let result = StorageBackendExplicit::new(&additional_config);
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            StorageManagerInitializationError::MissingProviderImplConfigOption { .. }
        ))
    }

    #[rstest]
    fn test_invalid_creation_conflicting_config() {
        let mut provider_impl = TEST_KV_STORE.impl_config();
        provider_impl
            .additional_config
            .push(AdditionalConfig::FileStoreConfig {
                db_dir: TEST_TMP_DIR
                    .path()
                    .join("test_invalid_creation_conflicting_config")
                    .to_string_lossy()
                    .to_string(),
            });

        let result = StorageBackendExplicit::new(&provider_impl.additional_config);
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            StorageManagerInitializationError::ConflictingProviderImplConfig { .. }
        ))
    }

    #[rstest]
    fn test_insert(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        storage.store(scoped_key, b"TEST_DATA").unwrap();
    }

    #[rstest]
    fn test_insert_and_get(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        let data = b"TEST_DATA".to_vec();
        storage.store(scoped_key.clone(), &data).unwrap();

        let loaded_data = storage.get(scoped_key).unwrap();

        assert_eq!(data, loaded_data);
    }

    #[rstest]
    fn test_overwrite(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        let data1 = b"TEST_DATA".to_vec();
        storage.store(scoped_key.clone(), &data1).unwrap();
        let loaded_data_1 = storage.get(scoped_key.clone()).unwrap();
        assert_eq!(data1, loaded_data_1);

        let data2 = b"TEST_DATA_OVERWRITE".to_vec();
        storage.store(scoped_key.clone(), &data2).unwrap();
        let loaded_data_2 = storage.get(scoped_key).unwrap();
        assert_eq!(data2, loaded_data_2);
    }

    #[rstest]
    fn test_fail_key_not_exists(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        let result = storage.get(scoped_key);
        let error = result.unwrap_err();
        assert!(matches!(
            error,
            StorageBackendError::Sqlite(SqliteBackendError::NoKeyError)
                | StorageBackendError::KvStore(KvStorageBackendError::Get)
        ))
    }

    #[rstest]
    fn test_inserted_key_in_keys(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        storage.store(scoped_key.clone(), b"TEST_DATA").unwrap();

        let keys = storage.keys();

        assert!(keys
            .into_iter()
            .filter_map(|r| r.ok())
            .contains(&scoped_key))
    }

    #[rstest]
    fn test_keys_all_ok(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        storage.store(scoped_key.clone(), b"TEST_DATA").unwrap();

        let keys = storage.keys();

        assert!(keys.into_iter().all(|result| result.is_ok()))
    }

    #[rstest]
    fn test_delete(
        #[values(create_file_storage_backend, create_kv_storage_backend)]
        create: impl Fn() -> StorageBackendExplicit,
    ) {
        let storage = create();

        let scoped_key = random_scoped_key();

        let data = b"TEST_DATA".to_vec();
        storage.store(scoped_key.clone(), &data).unwrap();

        let loaded_data = storage.get(scoped_key.clone()).unwrap();

        assert_eq!(data, loaded_data);

        storage.delete(scoped_key.clone()).unwrap();

        let error = storage.get(scoped_key).unwrap_err();
        assert!(matches!(
            error,
            StorageBackendError::Sqlite(SqliteBackendError::NoKeyError)
                | StorageBackendError::KvStore(KvStorageBackendError::Get)
        ));
    }
}

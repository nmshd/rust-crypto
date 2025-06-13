use std::fs::canonicalize;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};
use std::{collections::HashMap, path::Path};

use itertools::Itertools;
use sled::{open, Db};
use thiserror::Error;

use crate::storage::key::ScopedKey;
use crate::storage::storage_backend::StorageBackendInitializationError;

use super::{StorageBackend, StorageBackendError};

/// Sled can only open a file once. This static holds the absolute path of a file and the open [Db].
static FILE_STORAGE_BACKEND_MAP: LazyLock<RwLock<HashMap<PathBuf, Db>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Error)]
pub enum FileStorageBackendError {
    #[error("Failed to serialize scoped key to json.")]
    ScopeSerialize { source: rmp_serde::encode::Error },
    #[error("Failed to deserialize json to scoped key.")]
    ScopeDeserialize { source: rmp_serde::decode::Error },
    #[error("Failed to insert data into database.")]
    Insert { source: sled::Error },
    #[error("Failed to get data from database.")]
    Get { source: sled::Error },
    #[error("The requested data does not exist.")]
    NotExists,
    #[error("Failed to delete data.")]
    Delete { source: sled::Error },
}

#[derive(Debug, Error)]
pub enum FileStorageBackendInitializationError {
    #[error("Failed to acquire lock for global map containing initialized file stores.")]
    AcquireLock,
    #[error("Failed to canonicalize input database path: '{path:?}'")]
    Canonicalize {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("Failed to create directories of database path.")]
    CreateDir {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("Failed to open db at path: '{path:?}'")]
    Open { source: sled::Error, path: PathBuf },
}

fn db_from_map(path: &PathBuf) -> Result<Option<Db>, StorageBackendInitializationError> {
    let db_map = FILE_STORAGE_BACKEND_MAP
        .read()
        .map_err(|_| FileStorageBackendInitializationError::AcquireLock)?;

    Ok(db_map.get(path).cloned())
}

fn insert_db_into_map(path: PathBuf, db: Db) -> Result<(), StorageBackendInitializationError> {
    let mut db_map = FILE_STORAGE_BACKEND_MAP
        .write()
        .map_err(|_| FileStorageBackendInitializationError::AcquireLock)?;

    db_map.insert(path, db);

    Ok(())
}

#[derive(Clone, Debug)]
pub struct FileStorageBackend {
    db: Db,
}

impl FileStorageBackend {
    /// Returns a [FileStorageBackend], for which a db is opened if not already opened.
    pub fn new(
        db_folder_path: impl AsRef<Path>,
    ) -> Result<Self, StorageBackendInitializationError> {
        if !db_folder_path.as_ref().exists() {
            std::fs::create_dir_all(db_folder_path.as_ref()).map_err(|err| {
                FileStorageBackendInitializationError::CreateDir {
                    source: err,
                    path: db_folder_path.as_ref().to_path_buf(),
                }
            })?;
        }

        let absolute_path = canonicalize(db_folder_path.as_ref()).map_err(|err| {
            FileStorageBackendInitializationError::Canonicalize {
                source: err,
                path: db_folder_path.as_ref().to_owned(),
            }
        })?;

        if let Some(db) = db_from_map(&absolute_path)? {
            return Ok(Self { db: db.clone() });
        }

        let db =
            open(&absolute_path).map_err(|err| FileStorageBackendInitializationError::Open {
                source: err,
                path: absolute_path.clone(),
            })?;

        insert_db_into_map(absolute_path, db.clone())?;

        Ok(Self { db: db })
    }
}

fn serialize_scoped_key(key: &ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
    rmp_serde::to_vec_named(key)
        .map_err(|err| FileStorageBackendError::ScopeSerialize { source: err }.into())
}

fn deserialize_scoped_key(value: &[u8]) -> Result<ScopedKey, StorageBackendError> {
    rmp_serde::from_slice(value)
        .map_err(|err| FileStorageBackendError::ScopeDeserialize { source: err }.into())
}

impl StorageBackend for FileStorageBackend {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(&key)?;
        self.db
            .insert(key, data)
            .map_err(|err| FileStorageBackendError::Insert { source: err })?;
        Ok(())
    }

    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
        let key = serialize_scoped_key(&key)?;
        match self
            .db
            .get(key)
            .map_err(|err| FileStorageBackendError::Get { source: err })?
        {
            Some(data) => Ok(data.as_ref().to_vec()),
            None => Err(FileStorageBackendError::NotExists.into()),
        }
    }

    fn delete(&self, key: ScopedKey) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(&key)?;
        self.db
            .remove(key)
            .map_err(|err| FileStorageBackendError::Delete { source: err })?;

        Ok(())
    }

    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>> {
        self.db
            .iter()
            .keys()
            .map(|result| result.map_err(|err| FileStorageBackendError::Get { source: err }.into()))
            .map_ok(|raw_key| deserialize_scoped_key(&raw_key))
            .flatten_ok()
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_file_store_creation() {
        const DB_DIR_PATH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/file_store_test_db/test_file_store_creation"
        );

        let _storage = FileStorageBackend::new(DB_DIR_PATH).expect("Failed to create a file store");
    }

    #[test]
    fn test_multi_file_store_creation_same_file() {
        const DB_DIR_PATH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/target/file_store_test_db/test_multi_file_store_creation_same_file"
        );

        let store1 = FileStorageBackend::new(DB_DIR_PATH).expect("Failed to create a file store 1");

        let store2 = FileStorageBackend::new(DB_DIR_PATH).expect("Failed to create a file store 2");

        assert_eq!(store1.db.checksum().unwrap(), store2.db.checksum().unwrap());
    }
}

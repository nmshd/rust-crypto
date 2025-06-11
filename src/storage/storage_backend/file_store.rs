use std::fs::canonicalize;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};
use std::{collections::HashMap, path::Path};

use anyhow::anyhow;
use itertools::Itertools;
use sled::{open, Db};

use crate::storage::key::ScopedKey;

use super::{StorageBackend, StorageBackendError};

/// Sled can only open a file once. This static holds the absolute path of a file and the open [Db].
static FILE_STORAGE_BACKEND_MAP: LazyLock<RwLock<HashMap<PathBuf, Db>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn db_from_map(path: &PathBuf) -> Result<Option<Db>, StorageBackendError> {
    let db_map = FILE_STORAGE_BACKEND_MAP
        .read()
        .map_err(|err| StorageBackendError::Open {
            description: "While reading global file storage backend map, failed acquiring read.",
            source: anyhow!(format!("{}", err)),
        })?;

    Ok(db_map.get(path).cloned())
}

fn insert_db_into_map(path: PathBuf, db: Db) -> Result<(), StorageBackendError> {
    let mut db_map = FILE_STORAGE_BACKEND_MAP
        .write()
        .map_err(|err| StorageBackendError::Open {
            description: "While reading global file storage backend map, failed acquiring WRITE.",
            source: anyhow!(format!("{}", err)),
        })?;

    db_map.insert(path, db);

    Ok(())
}

#[derive(Clone, Debug)]
pub struct FileStorageBackend {
    db: Db,
}

impl FileStorageBackend {
    /// Returns a [FileStorageBackend], for which a db is opened if not already opened.
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, StorageBackendError> {
        let absolute_path =
            canonicalize(db_path.as_ref()).map_err(|err| StorageBackendError::Open {
                source: anyhow!(err),
                description:
                    "While creating file storage backend, failed to canonicalize input path.",
            })?;

        if let Some(db) = db_from_map(&absolute_path)? {
            return Ok(Self { db: db.clone() });
        }

        let db = open(&absolute_path).map_err(|err| StorageBackendError::Open {
            source: anyhow!(err),
            description:
                "While creating file storage backend, failed to open or create db at input path.",
        })?;

        insert_db_into_map(absolute_path, db.clone())?;

        Ok(Self { db: db })
    }
}

fn serialize_scoped_key(key: &ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
    rmp_serde::to_vec_named(key).map_err(|err| StorageBackendError::Scope {
        description: "Failed to serialize scoped key.",
        source: anyhow!(err),
    })
}

fn deserialize_scoped_key(value: &[u8]) -> Result<ScopedKey, StorageBackendError> {
    rmp_serde::from_slice(value).map_err(|err| StorageBackendError::Scope {
        description: "Failed to deserialize scoped key.",
        source: anyhow!(err),
    })
}

impl StorageBackend for FileStorageBackend {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(&key)?;
        self.db
            .insert(key, data)
            .map_err(|err| StorageBackendError::Store {
                description: "Insert into sled db failed.",
                source: anyhow!(err),
            })?;
        Ok(())
    }

    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
        let key = serialize_scoped_key(&key)?;
        match self.db.get(key).map_err(|err| StorageBackendError::Get {
            description: "Get for sled db failed.",
            source: anyhow!(err),
        })? {
            Some(data) => Ok(data.as_ref().to_vec()),
            None => Err(StorageBackendError::NotExists),
        }
    }

    fn delete(&self, key: ScopedKey) -> Result<(), StorageBackendError> {
        let key = serialize_scoped_key(&key)?;
        self.db
            .remove(key)
            .map_err(|err| StorageBackendError::Delete {
                description: "Failed to delete sled key and value.",
                source: anyhow!(err),
            })?;

        Ok(())
    }

    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>> {
        self.db
            .iter()
            .keys()
            .map(|result| {
                result.map_err(|err| StorageBackendError::Get {
                    description: "Failed reading of key.",
                    source: anyhow!(err),
                })
            })
            .map_ok(|raw_key| deserialize_scoped_key(&raw_key))
            .flatten_ok()
            .collect()
    }
}

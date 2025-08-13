use core::fmt;
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};

use include_dir::{include_dir, Dir};
use itertools::Itertools;
use rusqlite::{named_params, Connection};
use rusqlite_migration::Migrations;
use thiserror::Error;

use crate::storage::{
    key::ScopedKey,
    storage_backend::{StorageBackend, StorageBackendError, StorageBackendInitializationError},
};

#[derive(Error, Debug)]
pub enum SqliteBackendError {
    #[error("Failed to execute sql query.")]
    SqlError(#[from] rusqlite::Error),
    #[error("Key not found.")]
    NoKeyError,
    #[error("Failed to acquire lock to SQLite connection.")]
    Acquire,
}

#[derive(Error, Debug)]
pub enum SqliteBackendInitializationError {
    #[error("Failed database migration: {source}")]
    Migration { source: rusqlite_migration::Error },
    #[error("Failed creating database dir '{path:?}' with error: {source}")]
    Mkdir {
        source: std::io::Error,
        path: PathBuf,
    },
    #[error("Failed to set SQLite pragmas: {source}")]
    Pragma { source: rusqlite::Error },
    #[error("Failed opening sqlite database with path '{path:?}' and error: {source}")]
    Open {
        source: rusqlite::Error,
        path: PathBuf,
    },
}

#[derive(Clone)]
pub(in crate::storage) struct SqliteBackend {
    connection: Arc<Mutex<Connection>>,
}

static MIGRATIONS: LazyLock<Migrations<'_>> = LazyLock::new(|| {
    static MIGRATION_DIR: Dir =
        include_dir!("$CARGO_MANIFEST_DIR/src/storage/storage_backend/sqlite_store/migrations");
    Migrations::from_directory(&MIGRATION_DIR).expect("Failed to parse migrations.")
});

impl SqliteBackend {
    pub(super) fn new(path: impl AsRef<Path>) -> Result<Self, StorageBackendInitializationError> {
        create_dir_all(&path).map_err(|err| SqliteBackendInitializationError::Mkdir {
            path: path.as_ref().to_path_buf(),
            source: err,
        })?;

        let path = path.as_ref().join("keys.db");

        tracing::trace!("opening sql db: {:?}", path);

        let mut conn =
            Connection::open(&path).map_err(|err| SqliteBackendInitializationError::Open {
                source: err,
                path: path,
            })?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|err| SqliteBackendInitializationError::Pragma { source: err })?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|err| SqliteBackendInitializationError::Pragma { source: err })?;
        conn.pragma_update(None, "busy_timeout", "15000")
            .map_err(|err| SqliteBackendInitializationError::Pragma { source: err })?;

        match MIGRATIONS.to_latest(&mut conn) {
            Ok(_) => (),
            e @ Err(rusqlite_migration::Error::RusqliteError {
                query: _,
                err:
                    rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error {
                            code: _,
                            extended_code: 1,
                        },
                        _,
                    ),
            }) => tracing::warn!("Cant run sqlite migration: {:?}", e),
            Err(e) => return Err(SqliteBackendInitializationError::Migration { source: e }.into()),
        }

        Ok(Self {
            connection: Arc::new(Mutex::new(conn)),
        })
    }
}

impl fmt::Debug for SqliteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteBackend").finish()
    }
}

impl StorageBackend for SqliteBackend {
    fn store(&self, key: ScopedKey, data: &[u8]) -> Result<(), StorageBackendError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| SqliteBackendError::Acquire)?;

        let mut statement = conn
            .prepare_cached(include_str!("queries/store.sql"))
            .map_err(|err| SqliteBackendError::SqlError(err))?;

        statement
            .execute(named_params! {
                ":id": key.key_id,
                ":provider": key.provider_scope,
                ":encryption_key_id": key.encryption_scope,
                ":signature_key_id": key.signature_scope,
                ":data_blob": data,
            })
            .map_err(|e| StorageBackendError::Sqlite(e.into()))?;

        Ok(())
    }

    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| SqliteBackendError::Acquire)?;

        let mut statement = conn
            .prepare_cached(include_str!("queries/get.sql"))
            .map_err(|err| SqliteBackendError::SqlError(err))?;

        let result = statement.query_one(
            named_params! {
                ":id": key.key_id,
                ":provider": key.provider_scope,
                ":encryption_key_id": key.encryption_scope,
                ":signature_key_id": key.signature_scope,
            },
            |row| row.get(0),
        );

        match result {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(StorageBackendError::Sqlite(SqliteBackendError::NoKeyError))
            }
            Err(e) => Err(StorageBackendError::Sqlite(SqliteBackendError::SqlError(e))),
        }
    }

    fn delete(&self, key: ScopedKey) -> Result<(), StorageBackendError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| SqliteBackendError::Acquire)?;

        let mut statement = conn
            .prepare_cached(include_str!("queries/delete.sql"))
            .map_err(|err| SqliteBackendError::SqlError(err))?;

        statement
            .execute(named_params! {
                ":id": key.key_id,
                ":provider": key.provider_scope,
                ":encryption_key_id": key.encryption_scope,
                ":signature_key_id": key.signature_scope,
            })
            .map_err(|e| StorageBackendError::Sqlite(SqliteBackendError::SqlError(e)))?;
        Ok(())
    }

    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>> {
        let conn = match self.connection.lock() {
            Ok(c) => c,
            Err(_) => return vec![Err(SqliteBackendError::Acquire.into())],
        };

        let statement = conn.prepare_cached(include_str!("queries/keys.sql"));

        match statement {
            Err(e) => {
                vec![Err(StorageBackendError::Sqlite(
                    SqliteBackendError::SqlError(e),
                ))]
            }
            Ok(mut stmt) => {
                let rows = stmt
                    .query_map((), |row| {
                        Ok(ScopedKey {
                            key_id: row.get(0)?,
                            provider_scope: row.get(1)?,
                            encryption_scope: row.get(2)?,
                            signature_scope: row.get(3)?,
                        })
                    })
                    .map(|res| res.collect::<Vec<Result<ScopedKey, rusqlite::Error>>>());
                vec![rows]
                    .into_iter()
                    .flatten_ok()
                    .map(|v| flatten_res(v))
                    .map(|v| {
                        v.map_err(|e| StorageBackendError::Sqlite(SqliteBackendError::SqlError(e)))
                    })
                    .collect_vec()
            }
        }
    }
}

fn flatten_res<T, E>(res: Result<Result<T, E>, E>) -> Result<T, E> {
    match res {
        Ok(inner) => inner,
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod test {
    use nanoid::nanoid;
    use rstest::{fixture, rstest};
    use tempfile::{tempdir_in, TempDir};

    use super::*;

    const TARGET_FOLDER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");

    #[fixture]
    fn temp_folder() -> TempDir {
        tempdir_in(TARGET_FOLDER).unwrap()
    }

    #[rstest]
    fn test_file_store_creation(temp_folder: TempDir) {
        let _storage = SqliteBackend::new(temp_folder.path().join("test_file_store_creation"))
            .expect("Failed to create a file store");
    }

    #[rstest]
    fn test_multi_file_store_creation_same_file(temp_folder: TempDir) {
        let db_dir = temp_folder
            .path()
            .join("test_multi_file_store_creation_same_file");

        let store1 = SqliteBackend::new(&db_dir).expect("Failed to create a file store 1");

        let store2 = SqliteBackend::new(db_dir).expect("Failed to create a file store 2");

        let key = ScopedKey {
            key_id: nanoid!(),
            provider_scope: nanoid!(),
            encryption_scope: nanoid!(),
            signature_scope: nanoid!(),
        };

        let data = b"Hello";

        store1.store(key.clone(), data).unwrap();

        let fetched_data = store2.get(key).unwrap();

        assert_eq!(&fetched_data, data);

        drop(store1);
        drop(store2);

        // std::fs::remove_dir_all(TEST_TMP_DIR.path()).unwrap();
    }
}

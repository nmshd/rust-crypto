use core::fmt;
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::Arc,
};

use itertools::Itertools;
use r2d2::{Builder, Pool};
use r2d2_sqlite::{
    rusqlite::{self, named_params},
    SqliteConnectionManager,
};
use rusqlite_migration::{Migrations, M};
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
    #[error("Failed to acquire SQLite pooled connection.")]
    Acquire { source: r2d2::Error },
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
    Open { source: r2d2::Error, path: PathBuf },
    #[error("Failed to acquire SQLite pooled connection.")]
    Acquire { source: r2d2::Error },
}

#[derive(Clone)]
pub(in crate::storage) struct SqliteBackend {
    pool: Arc<Pool<SqliteConnectionManager>>,
}

const MIGRATIONS_SLICE: &[M<'_>] = &[
    M::up("CREATE TABLE keys (id TEXT PRIMARY KEY, provider TEXT, encryption_key_id TEXT, signature_key_id TEXT, data_blob BLOB);"),
];
const MIGRATIONS: Migrations<'_> = Migrations::from_slice(MIGRATIONS_SLICE);

impl SqliteBackend {
    pub(super) fn new(path: impl AsRef<Path>) -> Result<Self, StorageBackendInitializationError> {
        create_dir_all(&path).map_err(|err| SqliteBackendInitializationError::Mkdir {
            path: path.as_ref().to_path_buf(),
            source: err,
        })?;

        let path = path.as_ref().join("keys.db");

        tracing::trace!("opening sql db: {:?}", path);

        let manager = SqliteConnectionManager::file(&path).with_init(|conn| {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            conn.pragma_update(None, "busy_timeout", "15000")?;

            Ok(())
        });
        let pool = Builder::new().build(manager).map_err(|err| {
            SqliteBackendInitializationError::Open {
                source: err,
                path: path,
            }
        })?;

        // This is ok, as conn only is mut to hinder nested transactions on one connection.
        // See `rusqlite::Transaction` for more info.
        let mut conn = pool
            .get()
            .map_err(|err| SqliteBackendInitializationError::Acquire { source: err })?;

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
            pool: Arc::new(pool),
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
        self.pool
            .get()
            .map_err(|err| SqliteBackendError::Acquire { source: err })?
            .execute(
                "INSERT INTO keys (id, provider, encryption_key_id, signature_key_id, data_blob) 
                    VALUES (:id, :provider, :encryption_key_id, :signature_key_id, :data_blob)
                    ON CONFLICT(id) DO UPDATE
                    SET data_blob=excluded.data_blob;",
                named_params! {
                    ":id": key.key_id,
                    ":provider": key.provider_scope,
                    ":encryption_key_id": key.encryption_scope,
                    ":signature_key_id": key.signature_scope,
                    ":data_blob": data,
                },
            )
            .map_err(|e| StorageBackendError::Sqlite(e.into()))?;
        Ok(())
    }

    fn get(&self, key: ScopedKey) -> Result<Vec<u8>, StorageBackendError> {
        let query =
            "SELECT data_blob FROM keys WHERE id = :id AND provider = :provider AND encryption_key_id = :encryption_key_id AND signature_key_id = :signature_key_id;";

        let result = self
            .pool
            .get()
            .map_err(|err| SqliteBackendError::Acquire { source: err })?
            .query_one(
                query,
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
        let query =
            "DELETE FROM keys WHERE id = :id AND provider = :provider AND encryption_key_id = :encryption_key_id AND signature_key_id = :signature_key_id;";

        self.pool
            .get()
            .map_err(|err| SqliteBackendError::Acquire { source: err })?
            .execute(
                query,
                named_params! {
                    ":id": key.key_id,
                    ":provider": key.provider_scope,
                    ":encryption_key_id": key.encryption_scope,
                    ":signature_key_id": key.signature_scope,
                },
            )
            .map_err(|e| StorageBackendError::Sqlite(SqliteBackendError::SqlError(e)))?;
        Ok(())
    }

    fn keys(&self) -> Vec<Result<ScopedKey, StorageBackendError>> {
        let conn = match self.pool.get() {
            Ok(c) => c,
            Err(err) => return vec![Err(SqliteBackendError::Acquire { source: err }.into())],
        };

        let query = "SELECT id, provider, encryption_key_id, signature_key_id FROM keys;";
        let statement = conn.prepare(query);
        match statement {
            Err(e) => {
                return vec![Err(StorageBackendError::Sqlite(
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
    use std::sync::LazyLock;

    use nanoid::nanoid;
    use tempfile::{tempdir_in, TempDir};

    use super::*;

    const TARGET_FOLDER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target");
    static TEST_TMP_DIR: LazyLock<TempDir> = LazyLock::new(|| tempdir_in(TARGET_FOLDER).unwrap());

    #[test]
    fn test_file_store_creation() {
        let _storage = SqliteBackend::new(TEST_TMP_DIR.path().join("test_file_store_creation"))
            .expect("Failed to create a file store");
    }

    #[test]
    fn test_multi_file_store_creation_same_file() {
        let db_dir = TEST_TMP_DIR
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
    }
}

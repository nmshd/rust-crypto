use core::fmt;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use itertools::Itertools;
use rusqlite::{named_params, Connection};
use rusqlite_migration::{Migrations, M};
use thiserror::Error;

use crate::storage::{
    key::ScopedKey,
    storage_backend::{StorageBackend, StorageBackendError, StorageBackendInitializationError},
};

#[derive(Error, Debug)]
pub enum SqliteBackendError {
    #[error("Failed to initialize database.")]
    InitialisationError(String),
    #[error("Failed to execute query.")]
    SqlError(#[from] rusqlite::Error),
    #[error("Key not found.")]
    NoKeyError,
}

#[derive(Clone)]
pub(in crate::storage) struct SqliteBackend {
    conn: Arc<Mutex<Connection>>,
}

const MIGRATIONS_SLICE: &[M<'_>] = &[
    M::up("CREATE TABLE keys (id TEXT PRIMARY KEY, provider TEXT, encryption_key_id TEXT, signature_key_id TEXT, data_blob BLOB);"),
];
const MIGRATIONS: Migrations<'_> = Migrations::from_slice(MIGRATIONS_SLICE);

impl SqliteBackend {
    pub(super) fn new(path: impl AsRef<Path>) -> Result<Self, StorageBackendInitializationError> {
        let path = path.as_ref().join("keys.db");

        tracing::trace!("opening sql db: {:?}", path);

        let mut conn = Connection::open(&path).map_err(|_| {
            StorageBackendInitializationError::Sqlite(SqliteBackendError::InitialisationError(
                format!("Can't open path: {:?}", path),
            ))
        })?;

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
            Err(e) => {
                return Err(StorageBackendInitializationError::Sqlite(
                    SqliteBackendError::InitialisationError(format!(
                        "Can't run sqlite migration: {:?}",
                        e
                    )),
                ))
            }
        }

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
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
        self.conn
            .lock()
            .unwrap()
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

        let result = self.conn.lock().unwrap().query_one(
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

        self.conn
            .lock()
            .unwrap()
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
        let conn = self.conn.lock().unwrap();

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

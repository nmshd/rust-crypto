use crate::common::config::{AllKeysFn, DeleteFn, GetFn, StoreFn};
use redb::{Database, ReadableTable};
use std::sync::Arc;

use super::METADATA_TABLE;

/// Struct representing a database for storing metadata and cryptographic keys.
#[derive(Clone)]
pub struct MetadataDatabase {
    db: Arc<Database>,
}

impl MetadataDatabase {
    /// Initializes a new `MetadataDatabase`, creating the database file if it doesn't exist.
    #[allow(dead_code)]
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Create or open the database file
        let db = Database::create(path)?;

        // Explicitly open `METADATA_TABLE` to ensure it exists
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(METADATA_TABLE).unwrap();
        }
        write_txn.commit().unwrap();

        Ok(Self { db: Arc::new(db) })
    }

    /// Creates a function for storing metadata key-value pairs.
    #[allow(dead_code)]
    pub fn create_store_fn(&self) -> StoreFn {
        let db = Arc::clone(&self.db);
        Arc::new(move |key: String, value: Vec<u8>| {
            let db = db.clone();
            Box::pin(async move {
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table = write_txn.open_table(METADATA_TABLE).unwrap();
                    table.insert(key.as_str(), &*value).unwrap();
                }
                write_txn.commit().unwrap();
                true
            })
        })
    }

    /// Creates a function for retrieving metadata associated with a key.
    #[allow(dead_code)]
    pub fn create_get_fn(&self) -> GetFn {
        let db = Arc::clone(&self.db);
        Arc::new(move |key: String| {
            let db = db.clone();
            Box::pin(async move {
                let read_txn = db.begin_read().unwrap();
                let table = read_txn.open_table(METADATA_TABLE).unwrap();
                let value = table.get(key.as_str());
                if let Ok(data) = value {
                    data.map(|v| v.value().to_vec())
                } else {
                    None
                }
            })
        })
    }

    /// Creates a function for deleting metadata associated with a key.
    #[allow(dead_code)]
    pub fn create_delete_fn(&self) -> DeleteFn {
        let db = Arc::clone(&self.db);
        Arc::new(move |key: String| {
            let db = db.clone();
            Box::pin(async move {
                let write_txn = db.begin_write().unwrap();
                {
                    let mut table = write_txn.open_table(METADATA_TABLE).unwrap();
                    table.remove(key.as_str()).unwrap();
                }
                write_txn.commit().unwrap();
            })
        })
    }

    /// Creates a function for listing all metadata keys.
    #[allow(dead_code)]
    pub fn create_all_keys_fn(&self) -> AllKeysFn {
        let db = Arc::clone(&self.db);
        Arc::new(move || {
            let db = db.clone();
            Box::pin(async move {
                let read_txn = db.begin_read().unwrap();
                let table = read_txn.open_table(METADATA_TABLE).unwrap();
                table
                    .iter()
                    .unwrap()
                    .map(|entry| entry.unwrap().0.value().to_string())
                    .collect::<Vec<String>>()
            })
        })
    }
}

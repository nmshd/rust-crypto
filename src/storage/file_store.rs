use std::path::Path;

use sled::{open, Db};

use crate::prelude::CalError;

fn file_store_key_id(provider: impl AsRef<str>, key: impl AsRef<str>) -> Vec<u8> {
    format!("{}:{}", provider.as_ref(), key.as_ref())
        .as_bytes()
        .to_vec()
}

#[derive(Clone, Debug)]
pub struct FileStore {
    db: Db,
}

impl FileStore {
    pub fn new(db_dir: impl AsRef<Path>) -> Result<Self, CalError> {
        Ok(Self { db: open(db_dir)? })
    }

    pub fn store(
        &self,
        provider: impl AsRef<str>,
        key: impl AsRef<str>,
        value: Vec<u8>,
    ) -> Result<(), CalError> {
        let id = file_store_key_id(provider, key);
        self.db.insert(id, value)?;
        Ok(())
    }

    pub fn get(
        &self,
        provider: impl AsRef<str>,
        key: impl AsRef<str>,
    ) -> Result<Vec<u8>, CalError> {
        let id = file_store_key_id(provider, key.as_ref());
        match self.db.get(id)? {
            Some(data) => Ok(data.as_ref().to_vec()),
            None => Err(CalError::missing_value(
                format!("Sled (db): No data found for key: {}", key.as_ref()),
                true,
                None,
            )),
        }
    }

    pub fn delete(&self, provider: impl AsRef<str>, key: impl AsRef<str>) {
        let id = file_store_key_id(provider, key.as_ref());
        match self.db.remove(id) {
            Ok(_) => {}
            Err(e) => {
                // TODO: Change delete to return result?
                tracing::error!(error = %e, "Storage Manager: Failed deletion of data for key {}", key.as_ref())
            }
        }
    }

    pub fn get_all_keys(&self, scope: impl AsRef<str>) -> Vec<Vec<u8>> {
        self.db
            .scan_prefix(file_store_key_id(scope, ""))
            .values()
            .filter(|result| match result {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(error = %e, "Sled (db): Failed reading entry.");
                    false
                }
            })
            .map(|result| result.unwrap().as_ref().to_vec())
            .collect()
    }
}

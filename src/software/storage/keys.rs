use securestore::{KeySource, SecretsManager};
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::common::error::CalError;

/// Struct representing the Key Manager using `securestore`.
pub struct KeyManager {
    secrets_manager: Arc<Mutex<SecretsManager>>,
}

impl KeyManager {
    /// Initializes a new `KeyManager` by loading an existing secrets store or creating a new one.
    ///
    /// # Arguments
    /// * `store_path` - Path to the secrets store file.
    /// * `key_source` - Source of the encryption/decryption key (password or key file).
    ///
    /// # Returns
    /// A `Result` with a new `KeyManager` instance or an error if initialization fails.
    #[allow(dead_code)]
    pub fn new(store_path: &str, key_source: KeySource) -> Result<Self, Box<dyn Error>> {
        let path = Path::new(store_path);
        let secrets_manager = if path.exists() {
            SecretsManager::load(store_path, key_source)?
        } else {
            let manager = SecretsManager::new(key_source.clone())?;
            manager.save_as(store_path)?;
            SecretsManager::load(store_path, key_source)?
        };
        Ok(Self {
            secrets_manager: Arc::new(Mutex::new(secrets_manager)),
        })
    }

    /// Stores a key in the secrets store.
    ///
    /// # Arguments
    /// * `key_id` - Identifier for the key.
    /// * `key_data` - The key data to store.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    #[allow(dead_code)]
    pub fn store_key(&self, key_id: &str, key_data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut manager = self.secrets_manager.lock().unwrap();
        manager.set(key_id, key_data);
        manager.save()?;
        Ok(())
    }

    /// Retrieves a key from the secrets store.
    ///
    /// # Arguments
    /// * `key_id` - Identifier for the key.
    ///
    /// # Returns
    /// An `Option` with the key data or `None` if retrieval fails.
    #[allow(dead_code)]
    pub fn retrieve_key(&self, key_id: &str) -> Option<Vec<u8>> {
        let manager = self.secrets_manager.lock().unwrap();
        manager
            .get(key_id)
            .ok()
            .map(|data| data.as_bytes().to_vec())
    }

    /// Lists all key identifiers in the secrets store.
    ///
    /// # Returns
    /// A `Result` with a vector of key identifiers or an error if listing fails.
    #[allow(dead_code)]
    pub fn list_keys(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let manager = self.secrets_manager.lock().unwrap();
        Ok(manager.keys().map(|key| key.to_owned()).collect())
    }

    /// Deletes a key from the secrets store.
    ///
    /// # Arguments
    /// * `key_id` - Identifier for the key to delete.
    ///
    /// # Returns
    /// A `Result` indicating success or failure.
    ///
    /// # Errors
    /// Returns an error if the key does not exist or if the deletion fails.
    #[allow(dead_code)]
    pub fn delete_key(&self, key_id: &str) -> Result<(), Box<dyn Error>> {
        let mut manager = self.secrets_manager.lock().unwrap();
        // Attempt to remove the key. The `remove` method returns an Option.
        if manager.remove(key_id).is_ok() {
            // If the key existed and was removed, save the updated store.
            manager.save()?;
            Ok(())
        } else {
            // If the key did not exist, return an error.
            Err(Box::new(CalError::failed_operation(
                format!("Key '{}' not found", key_id),
                false,
                None,
            )))
        }
    }

    #[allow(dead_code)]
    pub fn secrets_manager(&self) -> &Mutex<SecretsManager> {
        &self.secrets_manager
    }
}

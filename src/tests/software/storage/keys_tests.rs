#[cfg(test)]
mod tests {
    use crate::software::storage::keys::KeyManager;
    use securestore::KeySource;
    use std::error::Error;
    use tempfile::{Builder, TempDir};

    /// Helper function to create a `KeyManager` with a temporary secrets store.
    fn create_temp_key_manager(
        tempdir: &TempDir,
        password: &str,
    ) -> Result<KeyManager, Box<dyn Error>> {
        let store_path = tempdir.path().join("secrets.json");
        let store_path_str = store_path.to_str().unwrap();
        let key_source = KeySource::Password(password);
        let manager = KeyManager::new(store_path_str, key_source)?;

        Ok(manager)
    }

    #[test]
    fn test_store_and_retrieve_key() {
        let tempdir = Builder::new().prefix("key_manager_test").tempdir().unwrap();
        let key_manager = create_temp_key_manager(&tempdir, "password123").unwrap();

        // Store a key-value pair
        let key_id = "test_key";
        let key_data = b"super_secret_key_data";
        key_manager.store_key(key_id, key_data).unwrap();

        // Retrieve the stored key
        let retrieved_data = key_manager.retrieve_key(key_id);
        assert_eq!(
            retrieved_data,
            Some(key_data.to_vec()),
            "The retrieved data does not match the stored data"
        );
    }

    #[test]
    fn test_retrieve_nonexistent_key() {
        let tempdir = Builder::new().prefix("key_manager_test").tempdir().unwrap();
        let key_manager = create_temp_key_manager(&tempdir, "password123").unwrap();

        // Attempt to retrieve a key that doesn't exist
        let key_id = "nonexistent_key";
        let retrieved_data = key_manager.retrieve_key(key_id);
        assert!(
            retrieved_data.is_none(),
            "Nonexistent key should return None"
        );
    }

    #[test]
    fn test_list_keys() {
        let tempdir = Builder::new().prefix("key_manager_test").tempdir().unwrap();
        let key_manager = create_temp_key_manager(&tempdir, "password123").unwrap();

        // Store multiple keys
        let key1 = "key1";
        let key2 = "key2";
        key_manager.store_key(key1, b"value1").unwrap();
        key_manager.store_key(key2, b"value2").unwrap();

        // List all keys and verify they are present
        let keys = key_manager.list_keys().unwrap();
        assert_eq!(keys.len(), 2, "Expected two keys to be listed");
        assert!(
            keys.contains(&key1.to_string()),
            "Key1 should be in the key list"
        );
        assert!(
            keys.contains(&key2.to_string()),
            "Key2 should be in the key list"
        );
    }

    #[test]
    fn test_delete_key() {
        let tempdir = Builder::new().prefix("key_manager_test").tempdir().unwrap();
        let key_manager = create_temp_key_manager(&tempdir, "password123").unwrap();

        // Store and verify a key
        let key_id = "key_to_delete";
        let key_data = b"temporary_key_data";
        key_manager.store_key(key_id, key_data).unwrap();
        assert!(
            key_manager.retrieve_key(key_id).is_some(),
            "Key should exist before deletion"
        );

        // Delete the key
        key_manager
            .secrets_manager()
            .try_lock()
            .unwrap()
            .remove(key_id)
            .unwrap();
        key_manager
            .secrets_manager()
            .try_lock()
            .unwrap()
            .save()
            .unwrap();

        // Verify the key has been deleted
        assert!(
            key_manager.retrieve_key(key_id).is_none(),
            "Key should be deleted but still exists"
        );
    }

    #[test]
    fn test_persistent_storage_across_instances() {
        let temp_dir = Builder::new().prefix("key_manager_test").tempdir().unwrap();
        let store_path = temp_dir
            .path()
            .join("secrets.json")
            .to_str()
            .unwrap()
            .to_string();
        let key_source = KeySource::Password("password123");

        // First instance: store a key
        {
            let key_manager = KeyManager::new(&store_path, key_source.clone()).unwrap();
            let key_id = "persistent_key";
            let key_data = b"persistent_key_data";
            key_manager.store_key(key_id, key_data).unwrap();
        }

        // Second instance: verify the key can be retrieved
        {
            let key_manager = KeyManager::new(&store_path, key_source.clone()).unwrap();
            let retrieved_data = key_manager.retrieve_key("persistent_key");
            assert_eq!(
                retrieved_data,
                Some(b"persistent_key_data".to_vec()),
                "The retrieved data does not match the originally stored data"
            );
        }
    }
}

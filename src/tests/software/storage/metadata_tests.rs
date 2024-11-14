#[cfg(test)]
mod tests {
    use crate::software::storage::metadata::MetadataDatabase;
    use smol::block_on;
    use tempfile::Builder;

    /// Helper function to create a temporary `MetadataDatabase` instance.
    fn create_temp_metadata_db() -> MetadataDatabase {
        let dir = Builder::new().prefix("metadata_test").tempdir().unwrap();
        let db_path = dir.path().join("metadata_test.db");
        MetadataDatabase::new(db_path.to_str().unwrap()).unwrap()
    }

    #[test]
    fn test_store_and_retrieve_metadata() {
        let db = create_temp_metadata_db();
        let store_fn = db.create_store_fn();
        let get_fn = db.create_get_fn();

        // Store a key-value pair
        let key = "test_key".to_string();
        let value = b"test_value".to_vec();
        let result = block_on(store_fn(key.clone(), value.clone()));
        assert!(result, "Failed to store key-value pair");

        // Retrieve the stored value
        let retrieved_value = block_on(get_fn(key.clone()));
        assert_eq!(
            retrieved_value,
            Some(value),
            "Retrieved value does not match stored value"
        );
    }

    #[test]
    fn test_retrieve_nonexistent_key() {
        let db = create_temp_metadata_db();
        let get_fn = db.create_get_fn();

        // Attempt to retrieve a key that hasn't been stored
        let key = "nonexistent_key".to_string();
        let retrieved_value = block_on(get_fn(key));
        assert_eq!(retrieved_value, None, "Nonexistent key should return None");
    }

    #[test]
    fn test_list_keys() {
        let db = create_temp_metadata_db();
        let store_fn = db.create_store_fn();
        let all_keys_fn = db.create_all_keys_fn();

        // Store multiple key-value pairs
        let key1 = "key1".to_string();
        let key2 = "key2".to_string();
        let value = b"value".to_vec();
        block_on(store_fn(key1.clone(), value.clone()));
        block_on(store_fn(key2.clone(), value));

        // List all keys
        let keys = block_on(all_keys_fn());
        assert_eq!(keys.len(), 2, "Expected two keys to be stored");
        assert!(
            keys.contains(&key1),
            "Key1 should be present in the key list"
        );
        assert!(
            keys.contains(&key2),
            "Key2 should be present in the key list"
        );
    }

    #[test]
    fn test_delete_key() {
        let db = create_temp_metadata_db();
        let store_fn = db.create_store_fn();
        let get_fn = db.create_get_fn();
        let delete_fn = db.create_delete_fn();

        // Store a key-value pair
        let key = "delete_key".to_string();
        let value = b"to_be_deleted".to_vec();
        block_on(store_fn(key.clone(), value.clone()));

        // Verify the key was stored
        let retrieved_value = block_on(get_fn(key.clone()));
        assert_eq!(
            retrieved_value,
            Some(value),
            "Failed to store value before deletion"
        );

        // Delete the key
        block_on(delete_fn(key.clone()));

        // Verify the key is no longer present
        let retrieved_value_after_delete = block_on(get_fn(key));
        assert_eq!(
            retrieved_value_after_delete, None,
            "Key should be deleted but still exists"
        );
    }

    #[test]
    fn test_delete_nonexistent_key() {
        let db = create_temp_metadata_db();
        let delete_fn = db.create_delete_fn();
        let get_fn = db.create_get_fn();

        // Attempt to delete a non-existent key
        let key = "nonexistent_delete_key".to_string();
        block_on(delete_fn(key.clone()));

        // Ensure it does not throw errors and does not affect the non-existent key
        let retrieved_value = block_on(get_fn(key));
        assert_eq!(
            retrieved_value, None,
            "Non-existent key should remain unaffected"
        );
    }
}

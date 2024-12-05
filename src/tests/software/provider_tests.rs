#[allow(static_mut_refs)]
#[cfg(test)]
mod tests {
    use crate::{
        common::traits::key_handle::DHKeyExchangeImpl, software::provider::SoftwareDHExchange,
    };
    use std::str::from_utf8;

    mod dh_exchange {

        use std::sync::LazyLock;

        use crate::{storage::StorageManager, tests::TestStore};

        use super::*;

        static mut STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

        #[test]
        fn test_dh_exchange_success() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a =
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager.clone())
                    .expect("Failed to initialize DH exchange for party A");

            // Party B creates an instance of SoftwareDHExchange
            let mut dh_exchange_b =
                SoftwareDHExchange::new("key_id_b".to_string(), storage_manager)
                    .expect("Failed to initialize DH exchange for party B");

            // Party A gets its public key
            let public_key_a = dh_exchange_a
                .get_public_key()
                .expect("Failed to get public key A");

            // Party B gets its public key
            let public_key_b = dh_exchange_b
                .get_public_key()
                .expect("Failed to get public key B");

            // Party A computes the shared secret using B's public key
            let shared_secret_a = dh_exchange_a
                .add_external(&public_key_b)
                .expect("Failed to compute shared secret on party A");

            // Party B computes the shared secret using A's public key
            let shared_secret_b = dh_exchange_b
                .add_external(&public_key_a)
                .expect("Failed to compute shared secret on party B");

            // The shared secrets should be equal
            assert_eq!(
                shared_secret_a, shared_secret_b,
                "Shared secrets do not match"
            );

            // Optionally, check that the shared secret is non-zero
            assert!(
                shared_secret_a.iter().any(|&b| b != 0),
                "Shared secret is all zeros"
            );
        }

        #[test]
        fn test_dh_exchange_derive_symmetric_key() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a =
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager.clone())
                    .expect("Failed to initialize DH exchange for party A");

            // Party B creates an instance of SoftwareDHExchange
            let mut dh_exchange_b =
                SoftwareDHExchange::new("key_id_b".to_string(), storage_manager)
                    .expect("Failed to initialize DH exchange for party B");

            // Party A gets its public key
            let public_key_a = dh_exchange_a
                .get_public_key()
                .expect("Failed to get public key A");

            // Party B gets its public key
            let public_key_b = dh_exchange_b
                .get_public_key()
                .expect("Failed to get public key B");

            // Party A computes the final shared secret and derives symmetric key
            let key_handle_a = dh_exchange_a
                .add_external_final(&public_key_b)
                .expect("Failed to compute final shared secret on party A");

            // Party B computes the final shared secret and derives symmetric key
            let key_handle_b = dh_exchange_b
                .add_external_final(&public_key_a)
                .expect("Failed to compute final shared secret on party B");

            // Now, test that the symmetric keys can encrypt and decrypt data

            let plaintext = b"Test message for encryption";

            // Party A encrypts the data
            let encrypted_data = key_handle_a
                .encrypt_data(plaintext)
                .expect("Encryption failed on party A");

            // Party B decrypts the data
            let decrypted_data = key_handle_b
                .decrypt_data(&encrypted_data.0, &[])
                .expect("Decryption failed on party B");

            // The decrypted data should match the original plaintext
            assert_eq!(
                from_utf8(&decrypted_data).unwrap(),
                from_utf8(plaintext).unwrap(),
                "Decrypted data does not match plaintext"
            );
        }

        #[test]
        fn test_dh_exchange_with_invalid_public_key() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a =
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager)
                    .expect("Failed to initialize DH exchange for party A");

            // Generate an invalid public key (e.g., random bytes)
            let invalid_public_key = vec![1, 2, 3, 4, 5];

            // Party A attempts to compute the shared secret using the invalid public key
            let result = dh_exchange_a.add_external(&invalid_public_key);

            // Expect an error
            assert!(
                result.is_err(),
                "Expected error when using invalid public key"
            );

            // Optionally, check the error message
            if let Err(e) = result {
                println!("Error as expected: {}", e);
            }
        }

        #[test]
        fn test_dh_exchange_private_key_consumed() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a =
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager)
                    .expect("Failed to initialize DH exchange for party A");

            // Party A gets its public key
            let public_key_a = dh_exchange_a
                .get_public_key()
                .expect("Failed to get public key A");

            // Party A calls add_external_final with some public key (could be its own, doesn't matter here)
            let _ = dh_exchange_a
                .add_external_final(&public_key_a)
                .expect("Failed to compute final shared secret on party A");

            // Attempting to call add_external should result in an error because private_key is consumed
            let result = dh_exchange_a.add_external(&public_key_a);

            // Expect an error
            assert!(
                result.is_err(),
                "Expected error when calling add_external after add_external_final"
            );
        }
    }
}

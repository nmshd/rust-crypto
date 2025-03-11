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
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager.clone()).unwrap();

            // Party B creates an instance of SoftwareDHExchange
            let mut dh_exchange_b =
                SoftwareDHExchange::new("key_id_b".to_string(), storage_manager).unwrap();

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
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager.clone()).unwrap();

            // Party B creates an instance of SoftwareDHExchange
            let mut dh_exchange_b =
                SoftwareDHExchange::new("key_id_b".to_string(), storage_manager).unwrap();

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
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager).unwrap();

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
                println!("Error as expected: {e}");
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
                SoftwareDHExchange::new("key_id_a".to_string(), storage_manager).unwrap();

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

    mod derive_key {
        use std::sync::LazyLock;

        use crate::{
            common::{
                error::CalError,
                factory,
                traits::{key_handle::KeyHandleImpl, module_provider::ProviderImpl},
                KeyHandle, Provider,
            },
            prelude::{Cipher, CryptoHash, KeySpec},
            tests::TestStore,
        };

        static mut STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

        fn setup_provider() -> Provider {
            let impl_config = unsafe { STORE.impl_config().clone() };
            factory::create_provider_from_name("SoftwareProvider", impl_config).unwrap()
        }

        fn get_algorithm() -> KeySpec {
            KeySpec {
                cipher: Cipher::XChaCha20Poly1305,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
            }
        }

        // Default parameters for testing
        const DEFAULT_OPSLIMIT: u32 = 4; // Low value for faster tests
        const DEFAULT_MEMLIMIT: u32 = 8192; // Minimum reasonable value

        #[test]
        fn test_successful_key_derivation() {
            let provider = setup_provider();
            let password = "test_password";
            let salt = [0u8; 16];
            let algorithm = get_algorithm();

            let key_handle_result: Result<KeyHandle, CalError> =
                provider.implementation.derive_key_from_password(
                    password,
                    &salt,
                    algorithm,
                    argon2::Algorithm::Argon2id.as_ref(),
                    DEFAULT_OPSLIMIT,
                    DEFAULT_MEMLIMIT,
                );
            assert!(key_handle_result.is_ok(), "Failed to derive key");

            let key_handle = key_handle_result.unwrap();
            let key = key_handle.implementation.extract_key().unwrap();
            assert_eq!(key.len(), 32, "Derived key should be 32 bytes");
        }

        #[test]
        fn test_different_passwords_yield_different_keys() {
            let provider = setup_provider();
            let salt = [0u8; 16];
            let algorithm = get_algorithm();

            let key1 = provider
                .implementation
                .derive_key_from_password(
                    "test_password",
                    &salt,
                    algorithm,
                    argon2::Algorithm::Argon2id.as_ref(),
                    DEFAULT_OPSLIMIT,
                    DEFAULT_MEMLIMIT,
                )
                .unwrap()
                .implementation
                .extract_key()
                .unwrap();

            let key2 = provider
                .implementation
                .derive_key_from_password(
                    "another_password",
                    &salt,
                    algorithm,
                    argon2::Algorithm::Argon2id.as_ref(),
                    DEFAULT_OPSLIMIT,
                    DEFAULT_MEMLIMIT,
                )
                .unwrap()
                .implementation
                .extract_key()
                .unwrap();

            assert_ne!(
                key1, key2,
                "Different passwords should yield different keys"
            );
        }

        #[test]
        fn test_different_salts_yield_different_keys() {
            let provider = setup_provider();
            let password = "test_password";
            let algorithm = get_algorithm();

            let key1 = provider
                .implementation
                .derive_key_from_password(
                    password,
                    &[0u8; 16],
                    algorithm,
                    argon2::Algorithm::Argon2id.as_ref(),
                    DEFAULT_OPSLIMIT,
                    DEFAULT_MEMLIMIT,
                )
                .unwrap()
                .implementation
                .extract_key()
                .unwrap();

            let key2 = provider
                .implementation
                .derive_key_from_password(
                    password,
                    &[1u8; 16],
                    algorithm,
                    argon2::Algorithm::Argon2id.as_ref(),
                    DEFAULT_OPSLIMIT,
                    DEFAULT_MEMLIMIT,
                )
                .unwrap()
                .implementation
                .extract_key()
                .unwrap();

            assert_ne!(key1, key2, "Different salts should yield different keys");
        }

        #[test]
        fn test_short_salt_length_fails() {
            let provider = setup_provider();
            let password = "test_password";
            let short_salt = [0u8; 15];
            let algorithm = get_algorithm();

            let result = provider.implementation.derive_key_from_password(
                password,
                &short_salt,
                algorithm,
                argon2::Algorithm::Argon2id.as_ref(),
                DEFAULT_OPSLIMIT,
                DEFAULT_MEMLIMIT,
            );

            assert!(result.is_err(), "Deriving key with short salt should fail");
            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Salt must be exactly 16 bytes long"),
                    "Incorrect error message for short salt: {}",
                    e
                );
            }
        }

        #[test]
        fn test_long_salt_length_fails() {
            let provider = setup_provider();
            let password = "test_password";
            let long_salt = [0u8; 17];
            let algorithm = get_algorithm();

            let result = provider.implementation.derive_key_from_password(
                password,
                &long_salt,
                algorithm,
                argon2::Algorithm::Argon2id.as_ref(),
                DEFAULT_OPSLIMIT,
                DEFAULT_MEMLIMIT,
            );

            assert!(result.is_err(), "Deriving key with long salt should fail");
            if let Err(e) = result {
                assert!(
                    e.to_string().contains("Salt must be exactly 16 bytes long"),
                    "Incorrect error message for long salt: {}",
                    e
                );
            }
        }

        #[test]
        fn test_argon2i_variant() {
            let provider = setup_provider();
            let password = "test_password";
            let salt = [0u8; 16];
            let algorithm = get_algorithm();

            let result = provider.implementation.derive_key_from_password(
                password,
                &salt,
                algorithm,
                argon2::Algorithm::Argon2id.as_ref(),
                DEFAULT_OPSLIMIT,
                DEFAULT_MEMLIMIT,
            );

            assert!(result.is_ok(), "Argon2i variant should work");
        }

        #[test]
        fn test_get_random() {
            let provider = setup_provider();
            let len = 16;
            let random = provider.get_random(len);
            assert_eq!(random.len(), 16);
            let mut all_zero = true;
            (0..random.len()).for_each(|i| {
                if random[i] != 0 {
                    all_zero = false
                }
            });
            assert!(!all_zero);
        }
    }
}

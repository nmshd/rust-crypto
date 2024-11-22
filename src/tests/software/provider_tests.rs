#[cfg(test)]
mod tests {
    use crate::{
        common::{
            config::KeySpec,
            crypto::algorithms::{
                encryption::{Cipher, SymmetricMode},
                KeyBits,
            },
            error::CalError,
            factory,
            traits::key_handle::DHKeyExchangeImpl,
            traits::key_handle::{KeyHandleImpl, KeyHandleImplEnum},
            KeyHandle, Provider,
        },
        software::{key_handle::SoftwareKeyHandle, provider::SoftwareDHExchange, SoftwareProvider},
    };
    use ring::rand::{SecureRandom, SystemRandom};
    use std::str::from_utf8;
    use tempfile::Builder;

    mod dh_exchange {

        use super::*;

        #[test]
        fn test_dh_exchange_success() {
            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a = SoftwareDHExchange::new("key_id_a".to_string())
                .expect("Failed to initialize DH exchange for party A");

            // Party B creates an instance of SoftwareDHExchange
            let mut dh_exchange_b = SoftwareDHExchange::new("key_id_b".to_string())
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
            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a = SoftwareDHExchange::new("key_id_a".to_string())
                .expect("Failed to initialize DH exchange for party A");

            // Party B creates an instance of SoftwareDHExchange
            let mut dh_exchange_b = SoftwareDHExchange::new("key_id_b".to_string())
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
            let key_handle_impl_a = dh_exchange_a
                .add_external_final(&public_key_b)
                .expect("Failed to compute final shared secret on party A");

            // Party B computes the final shared secret and derives symmetric key
            let key_handle_impl_b = dh_exchange_b
                .add_external_final(&public_key_a)
                .expect("Failed to compute final shared secret on party B");

            // Extract the symmetric keys from the KeyHandleImplEnum
            let symmetric_key_handle_a = match key_handle_impl_a {
                KeyHandleImplEnum::SoftwareKeyHandle(handle) => handle,
                _ => panic!("Expected SoftwareKeyHandle for party A"),
            };

            let symmetric_key_handle_b = match key_handle_impl_b {
                KeyHandleImplEnum::SoftwareKeyHandle(handle) => handle,
                _ => panic!("Expected SoftwareKeyHandle for party B"),
            };

            // Now, test that the symmetric keys can encrypt and decrypt data

            let plaintext = b"Test message for encryption";

            // Party A encrypts the data
            let encrypted_data = symmetric_key_handle_a
                .encrypt_data(plaintext)
                .expect("Encryption failed on party A");

            // Party B decrypts the data
            let decrypted_data = symmetric_key_handle_b
                .decrypt_data(&encrypted_data)
                .expect("Decryption failed on party B");

            // The decrypted data should match the original plaintext
            assert_eq!(
                from_utf8(&decrypted_data).unwrap().replace("\0", ""),
                from_utf8(plaintext).unwrap().replace("\0", ""),
                "Decrypted data does not match plaintext"
            );
        }

        #[test]
        fn test_dh_exchange_with_invalid_public_key() {
            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a = SoftwareDHExchange::new("key_id_a".to_string())
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
            // Party A creates an instance of SoftwareDHExchange
            let mut dh_exchange_a = SoftwareDHExchange::new("key_id_a".to_string())
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

    mod provider {

        use super::*;
        use crate::{common::config::ConfigHandle, software::SoftwareProviderAdditionalConfig};
        use std::sync::Arc;

        fn create_software_key_handle(spec: KeySpec) -> Result<SoftwareKeyHandle, CalError> {
            let dir = Builder::new().prefix("metadata_test").tempdir().unwrap();
            let md_db_path = dir.path().join("metadata_test.db");
            let key_db_path = dir.path().join("keys_test.db");

            // Create an instance of the concrete config
            let software_config = SoftwareProviderAdditionalConfig {
                metadata_path: Some(md_db_path.to_str().unwrap().to_string()),
                keydb_path: Some(key_db_path.to_str().unwrap().to_string()),
                keydb_pw: Some("insecure".to_string()),
            };

            // Wrap it in a `ConfigHandle`
            let config_handle = ConfigHandle::new(Arc::new(software_config));

            // Obtain the default provider implementation configuration
            let provider_impl_config = SoftwareProvider::get_default_config(
                Some(config_handle.clone()),
                None,
                None,
                None,
                None,
            );

            // Create the provider
            let mut provider: Provider = factory::create_provider_from_name(
                "SoftwareProvider".to_owned(),
                provider_impl_config,
            )
            .unwrap();

            // Create the key and extract the software key handle
            let key_handle = provider.create_key(spec)?;
            extract_software_key_handle(&key_handle)
        }

        fn extract_software_key_handle(
            key_handle: &KeyHandle,
        ) -> Result<SoftwareKeyHandle, CalError> {
            if let KeyHandleImplEnum::SoftwareKeyHandle(ref handle) = key_handle.implementation {
                Ok(handle.clone())
            } else {
                Err(CalError::failed_operation(
                    "Expected SoftwareKeyHandle".to_string(),
                    true,
                    None,
                ))
            }
        }

        #[test]
        fn test_encrypt_decrypt_data() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();
            let plaintext = b"Test data for encryption and decryption via provider.";

            let encrypted_data = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            assert_ne!(
                encrypted_data, plaintext,
                "Encrypted data should not match plaintext"
            );

            let decrypted_data = software_key_handle
                .decrypt_data(&encrypted_data)
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data).unwrap().replace('\0', ""),
                from_utf8(plaintext).unwrap().replace('\0', ""),
                "Decrypted data does not match original plaintext"
            );
        }

        #[test]
        fn test_encrypt_decrypt_empty_data() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits128),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext: &[u8] = &[];

            let encrypted_data = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let decrypted_data = software_key_handle
                .decrypt_data(&encrypted_data)
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data).unwrap().replace('\0', ""),
                from_utf8(plaintext).unwrap().replace('\0', ""),
                "Decrypted data does not match original plaintext"
            );
        }

        #[test]
        fn test_decrypt_with_wrong_key() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let software_key_handle1 = create_software_key_handle(spec).unwrap();
            let software_key_handle2 = create_software_key_handle(spec).unwrap();

            let plaintext = b"Data encrypted with key 1";

            let encrypted_data = software_key_handle1
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let decrypted_result = software_key_handle2.decrypt_data(&encrypted_data);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with wrong key"
            );
        }

        #[test]
        fn test_decrypt_modified_ciphertext() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext = b"Data to encrypt and then tamper with.";

            let mut encrypted_data = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            encrypted_data[15] ^= 0xFF;

            let decrypted_result = software_key_handle.decrypt_data(&encrypted_data);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with tampered ciphertext"
            );
        }

        #[test]
        fn test_id_method() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits128),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let key_id = software_key_handle.id().unwrap();

            assert!(!key_id.is_empty(), "Key ID should not be empty");
        }

        #[test]
        fn test_encrypt_decrypt_large_data() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext = vec![0x61; 1_048_576]; // 1 MB of data

            let encrypted_data = software_key_handle
                .encrypt_data(&plaintext)
                .expect("Encryption failed");

            let decrypted_data = software_key_handle
                .decrypt_data(&encrypted_data)
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data).unwrap().replace('\0', ""),
                from_utf8(&plaintext).unwrap().replace('\0', ""),
                "Decrypted data does not match original plaintext"
            );
        }

        #[test]
        fn test_encrypt_same_plaintext_multiple_times() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits128),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext = b"Same plaintext encrypted multiple times";

            let encrypted_data1 = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let encrypted_data2 = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            assert_ne!(
                encrypted_data1, encrypted_data2,
                "Encrypted data should differ with different nonces"
            );

            let decrypted_data1 = software_key_handle
                .decrypt_data(&encrypted_data1)
                .expect("Decryption failed");

            let decrypted_data2 = software_key_handle
                .decrypt_data(&encrypted_data2)
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data1).unwrap().replace('\0', ""),
                from_utf8(plaintext).unwrap().replace('\0', ""),
                "First decrypted data does not match plaintext"
            );
            assert_eq!(
                from_utf8(&decrypted_data2).unwrap().replace('\0', ""),
                from_utf8(plaintext).unwrap().replace('\0', ""),
                "Second decrypted data does not match plaintext"
            );
        }

        #[test]
        fn test_decrypt_random_data() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let mut random_data = vec![0u8; 50];
            let rng = SystemRandom::new();
            rng.fill(&mut random_data).unwrap();

            let decrypted_result = software_key_handle.decrypt_data(&random_data);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with random data"
            );
        }

        #[test]
        fn test_decrypt_short_data() {
            let spec = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();
            let short_data = vec![0u8; 10];
            let decrypted_result = software_key_handle.decrypt_data(&short_data);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with insufficient data"
            );
        }

        #[test]
        fn test_encrypt_decrypt_different_cipher_spec() {
            let spec256 = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                ..Default::default()
            };

            let spec128 = KeySpec {
                cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits128),
                ..Default::default()
            };

            let software_key_handle256 = create_software_key_handle(spec256).unwrap();
            let software_key_handle128 = create_software_key_handle(spec128).unwrap();

            let plaintext = b"Testing encryption with different cipher specs";

            let encrypted_data = software_key_handle256
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let decrypted_result = software_key_handle128.decrypt_data(&encrypted_data);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with different cipher spec"
            );
        }

        #[test]
        fn test_encrypt_decrypt_multiple_keys() {
            let specs = vec![
                KeySpec {
                    cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits128),
                    ..Default::default()
                },
                KeySpec {
                    cipher: Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits256),
                    ..Default::default()
                },
            ];

            let plaintext = b"Testing multiple keys";

            for spec in specs {
                let software_key_handle = create_software_key_handle(spec).unwrap();

                let encrypted_data = software_key_handle
                    .encrypt_data(plaintext)
                    .expect("Encryption failed");

                let decrypted_data = software_key_handle
                    .decrypt_data(&encrypted_data)
                    .expect("Decryption failed");

                assert_eq!(
                    from_utf8(&decrypted_data).unwrap().replace('\0', ""),
                    from_utf8(plaintext).unwrap().replace('\0', ""),
                    "Decrypted data does not match plaintext"
                );
            }
        }
    }
}

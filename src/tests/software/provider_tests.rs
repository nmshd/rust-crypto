#[allow(static_mut_refs)]
#[cfg(test)]
mod tests {
    use crate::{
        common::traits::key_handle::DHKeyExchangeImpl, prelude::*,
        software::provider::SoftwareDHExchange,
    };

    mod dh_exchange {
        use super::*;
        use crate::software::key_handle::SoftwareKeyHandle;
        use crate::{storage::StorageManager, tests::TestStore};
        use nanoid::nanoid;
        use std::str::from_utf8;
        use std::sync::LazyLock;

        static mut STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

        #[test]
        fn test_dh_exchange_client_server_keys() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            let key_pair_spec_list = [
                // Key pair spec similar to ts-crypto default.
                KeyPairSpec {
                    asym_spec: AsymmetricKeySpec::Curve25519,
                    cipher: Some(Cipher::XChaCha20Poly1305),
                    signing_hash: CryptoHash::Sha2_512,
                    ephemeral: false,
                    non_exportable: false,
                },
                // Similar to new default
                KeyPairSpec {
                    asym_spec: AsymmetricKeySpec::P256,
                    cipher: Some(Cipher::AesGcm256),
                    signing_hash: CryptoHash::Sha2_512,
                    ephemeral: false,
                    non_exportable: true,
                },
                // No cipher
                KeyPairSpec {
                    asym_spec: AsymmetricKeySpec::P256,
                    cipher: None,
                    signing_hash: CryptoHash::Sha2_512,
                    ephemeral: false,
                    non_exportable: true,
                },
            ];

            for key_pair_spec in key_pair_spec_list {
                // Client creates an instance of SoftwareDHExchange
                let mut client_exchange = SoftwareDHExchange::new(
                    "key_id_client".to_string(),
                    storage_manager.clone(),
                    key_pair_spec,
                )
                .unwrap();

                // Server creates an instance of SoftwareDHExchange
                let mut server_exchange = SoftwareDHExchange::new(
                    "key_id_server".to_string(),
                    storage_manager.clone(),
                    key_pair_spec,
                )
                .unwrap();

                // Client gets its public key
                let client_public_key = client_exchange
                    .get_public_key()
                    .expect("Failed to get client public key");

                // Server gets its public key
                let server_public_key = server_exchange
                    .get_public_key()
                    .expect("Failed to get server public key");

                // Client computes session keys using server's public key
                let (client_rx, client_tx) = client_exchange
                    .derive_client_session_keys(&server_public_key)
                    .expect("Failed to derive client session keys");

                // Server computes session keys using client's public key
                let (server_rx, server_tx) = server_exchange
                    .derive_server_session_keys(&client_public_key)
                    .expect("Failed to derive server session keys");

                // Verify complementary key derivation:
                // Client's transmit key should equal server's receive key
                assert_eq!(
                    client_tx, server_rx,
                    "Client's transmit key doesn't match server's receive key"
                );

                // Client's receive key should equal server's transmit key
                assert_eq!(
                    client_rx, server_tx,
                    "Client's receive key doesn't match server's transmit key"
                );

                // Verify keys are not empty or all zeros
                assert!(!client_rx.is_empty(), "Client receive key is empty");
                assert!(!client_tx.is_empty(), "Client transmit key is empty");
                assert!(
                    client_rx.iter().any(|&b| b != 0),
                    "Client receive key is all zeros"
                );
                assert!(
                    client_tx.iter().any(|&b| b != 0),
                    "Client transmit key is all zeros"
                );
            }
        }

        #[test]
        fn test_dh_exchange_encrypt_decrypt() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            let key_pair_spec_list = [
                // Key pair spec similar to ts-crypto default.
                KeyPairSpec {
                    asym_spec: AsymmetricKeySpec::Curve25519,
                    cipher: Some(Cipher::XChaCha20Poly1305),
                    signing_hash: CryptoHash::Sha2_512,
                    ephemeral: false,
                    non_exportable: false,
                },
                // Similar to new default
                KeyPairSpec {
                    asym_spec: AsymmetricKeySpec::P256,
                    cipher: Some(Cipher::AesGcm256),
                    signing_hash: CryptoHash::Sha2_512,
                    ephemeral: false,
                    non_exportable: true,
                },
                // No cipher
                KeyPairSpec {
                    asym_spec: AsymmetricKeySpec::P256,
                    cipher: None,
                    signing_hash: CryptoHash::Sha2_512,
                    ephemeral: false,
                    non_exportable: true,
                },
            ];

            for key_pair_spec in key_pair_spec_list {
                // Client creates an instance of SoftwareDHExchange
                let mut client_exchange = SoftwareDHExchange::new(
                    "key_id_client".to_string(),
                    storage_manager.clone(),
                    key_pair_spec,
                )
                .unwrap();

                // Server creates an instance of SoftwareDHExchange
                let mut server_exchange = SoftwareDHExchange::new(
                    "key_id_server".to_string(),
                    storage_manager.clone(),
                    key_pair_spec,
                )
                .unwrap();

                // Get public keys
                let client_public_key = client_exchange
                    .get_public_key()
                    .expect("Failed to get client public key");

                let server_public_key = server_exchange
                    .get_public_key()
                    .expect("Failed to get server public key");

                // Derive session keys
                let (client_rx, client_tx) = client_exchange
                    .derive_client_session_keys(&server_public_key)
                    .expect("Failed to derive client session keys");

                let (server_rx, server_tx) = server_exchange
                    .derive_server_session_keys(&client_public_key)
                    .expect("Failed to derive server session keys");

                // Create key handles for encryption/decryption
                let client_tx_key_id = nanoid!(10);
                let client_tx_handle = SoftwareKeyHandle {
                    key_id: client_tx_key_id.clone(),
                    key: client_tx,
                    storage_manager: storage_manager.clone(),
                    spec: KeySpec {
                        cipher: Cipher::AesGcm256,
                        ephemeral: true,
                        signing_hash: CryptoHash::Sha2_256,
                    },
                };
                let client_tx_key_handle = KeyHandle {
                    implementation: client_tx_handle.into(),
                };

                let server_rx_key_id = nanoid!(10);
                let server_rx_handle = SoftwareKeyHandle {
                    key_id: server_rx_key_id.clone(),
                    key: server_rx,
                    storage_manager: storage_manager.clone(),
                    spec: KeySpec {
                        cipher: Cipher::AesGcm256,
                        ephemeral: true,
                        signing_hash: CryptoHash::Sha2_256,
                    },
                };
                let server_rx_key_handle = KeyHandle {
                    implementation: server_rx_handle.into(),
                };

                // Test message encryption/decryption client → server
                let plaintext = b"Message from client to server";

                // Client encrypts with their tx key
                let encrypted_data = client_tx_key_handle
                    .encrypt_data(plaintext)
                    .expect("Encryption failed on client");

                // Server decrypts with their rx key
                let decrypted_data = server_rx_key_handle
                    .decrypt_data(&encrypted_data.0, &[])
                    .expect("Decryption failed on server");

                assert_eq!(
                    from_utf8(&decrypted_data).unwrap(),
                    from_utf8(plaintext).unwrap(),
                    "Decrypted data does not match plaintext"
                );

                // Also test server → client communication using the other keys
                let server_tx_key_id = nanoid!(10);
                let server_tx_handle = SoftwareKeyHandle {
                    key_id: server_tx_key_id.clone(),
                    key: server_tx,
                    storage_manager: storage_manager.clone(),
                    spec: KeySpec {
                        cipher: Cipher::AesGcm256,
                        ephemeral: true,
                        signing_hash: CryptoHash::Sha2_256,
                    },
                };
                let server_tx_key_handle = KeyHandle {
                    implementation: server_tx_handle.into(),
                };

                let client_rx_key_id = nanoid!(10);
                let client_rx_handle = SoftwareKeyHandle {
                    key_id: client_rx_key_id.clone(),
                    key: client_rx,
                    storage_manager: storage_manager.clone(),
                    spec: KeySpec {
                        cipher: Cipher::AesGcm256,
                        ephemeral: true,
                        signing_hash: CryptoHash::Sha2_256,
                    },
                };
                let client_rx_key_handle = KeyHandle {
                    implementation: client_rx_handle.into(),
                };

                let server_plaintext = b"Message from server to client";

                // Server encrypts with their tx key
                let server_encrypted = server_tx_key_handle
                    .encrypt_data(server_plaintext)
                    .expect("Encryption failed on server");

                // Client decrypts with their rx key
                let client_decrypted = client_rx_key_handle
                    .decrypt_data(&server_encrypted.0, &[])
                    .expect("Decryption failed on client");

                assert_eq!(
                    from_utf8(&client_decrypted).unwrap(),
                    from_utf8(server_plaintext).unwrap(),
                    "Server-to-client decrypted data does not match plaintext"
                );
            }
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

            // Client creates an instance of SoftwareDHExchange
            let mut client_exchange = SoftwareDHExchange::new(
                "key_id_client".to_string(),
                storage_manager,
                KeyPairSpec::default(),
            )
            .unwrap();

            // Generate an invalid public key (too short for X25519)
            let invalid_public_key = vec![1, 2, 3, 4, 5];

            // Client attempts to derive session keys using the invalid public key
            let result = client_exchange.derive_client_session_keys(&invalid_public_key);

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

            // Client creates an instance of SoftwareDHExchange
            let mut client_exchange = SoftwareDHExchange::new(
                "key_id_client".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )
            .unwrap();

            // Generate a valid server public key
            let server_exchange = SoftwareDHExchange::new(
                "key_id_server".to_string(),
                storage_manager,
                KeyPairSpec::default(),
            )
            .unwrap();
            let server_public_key = server_exchange.get_public_key().unwrap();

            // Client derives session keys once
            let _ = client_exchange
                .derive_client_session_keys(&server_public_key)
                .expect("Failed to derive client session keys");

            // Attempting to derive keys again should fail because private_key was consumed
            let result = client_exchange.derive_client_session_keys(&server_public_key);

            // Expect an error
            assert!(
                result.is_err(),
                "Expected error when calling derive_client_session_keys after private key consumed"
            );

            // The error should indicate that the private key is no longer available
            if let Err(e) = result {
                assert!(
                    e.to_string().contains("No private key available"),
                    "Unexpected error message: {e}"
                );
            }
        }

        #[test]
        fn test_multiple_key_derivations() {
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })
                .unwrap()
                .unwrap(),
            );

            // Client1 creates an instance of SoftwareDHExchange
            let mut client1_exchange = SoftwareDHExchange::new(
                "key_id_client1".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )
            .unwrap();

            // Client2 creates an instance of SoftwareDHExchange
            let mut client2_exchange = SoftwareDHExchange::new(
                "key_id_client2".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )
            .unwrap();

            // Server instances for each client
            let mut server_for_client1 = SoftwareDHExchange::new(
                "key_id_server_for_client1".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )
            .unwrap();
            let mut server_for_client2 = SoftwareDHExchange::new(
                "key_id_server_for_client2".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )
            .unwrap();

            // Get public keys
            let client1_public_key = client1_exchange.get_public_key().unwrap();
            let client2_public_key = client2_exchange.get_public_key().unwrap();
            let server1_public_key = server_for_client1.get_public_key().unwrap();
            let server2_public_key = server_for_client2.get_public_key().unwrap();

            // Derive keys for Client1 and Server1
            let (client1_rx, client1_tx) = client1_exchange
                .derive_client_session_keys(&server1_public_key)
                .expect("Failed to derive client1 session keys");

            let (server1_rx, server1_tx) = server_for_client1
                .derive_server_session_keys(&client1_public_key)
                .expect("Failed to derive server keys for client1");

            // Verify key complementarity for first client
            assert_eq!(
                client1_tx, server1_rx,
                "Client1's transmit key should match server's receive key"
            );
            assert_eq!(
                client1_rx, server1_tx,
                "Client1's receive key should match server's transmit key"
            );

            // Derive keys for Client2 and Server2
            let (client2_rx, client2_tx) = client2_exchange
                .derive_client_session_keys(&server2_public_key)
                .expect("Failed to derive client2 session keys");

            let (server2_rx, server2_tx) = server_for_client2
                .derive_server_session_keys(&client2_public_key)
                .expect("Failed to derive server keys for client2");

            // Verify key complementarity for second client
            assert_eq!(
                client2_tx, server2_rx,
                "Client2's transmit key should match server's receive key"
            );
            assert_eq!(
                client2_rx, server2_tx,
                "Client2's receive key should match server's transmit key"
            );

            // Ensure different clients get different keys
            assert_ne!(
                client1_tx, client2_tx,
                "Different clients should get different transmit keys"
            );
            assert_ne!(
                client1_rx, client2_rx,
                "Different clients should get different receive keys"
            );
        }
    }

    mod derive_key {
        use super::*;
        use std::sync::LazyLock;

        use crate::{
            common::traits::{key_handle::KeyHandleImpl, module_provider::ProviderImpl},
            tests::TestStore,
        };

        static mut STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

        fn setup_provider() -> Provider {
            let impl_config = unsafe { STORE.impl_config().clone() };
            create_provider_from_name("SoftwareProvider", impl_config).unwrap()
        }

        fn get_algorithm() -> KeySpec {
            KeySpec {
                cipher: Cipher::XChaCha20Poly1305,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
            }
        }

        // Default parameters for testing
        const DEFAULT_KDF: KDF = KDF::Argon2id(Argon2Options {
            memory: 8192,  // Minimum reasonable value
            iterations: 4, // Low value for faster tests
            parallelism: 1,
        });

        #[test]
        fn test_successful_key_derivation() {
            let provider = setup_provider();
            let password = "test_password";
            let salt = [0u8; 16];
            let algorithm = get_algorithm();

            let key_handle_result: Result<KeyHandle, CalError> = provider
                .implementation
                .derive_key_from_password(password, &salt, algorithm, DEFAULT_KDF);
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
                .derive_key_from_password("test_password", &salt, algorithm, DEFAULT_KDF)
                .unwrap()
                .implementation
                .extract_key()
                .unwrap();

            let key2 = provider
                .implementation
                .derive_key_from_password("another_password", &salt, algorithm, DEFAULT_KDF)
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
                .derive_key_from_password(password, &[0u8; 16], algorithm, DEFAULT_KDF)
                .unwrap()
                .implementation
                .extract_key()
                .unwrap();

            let key2 = provider
                .implementation
                .derive_key_from_password(password, &[1u8; 16], algorithm, DEFAULT_KDF)
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
            let short_salt = [0u8; 7];
            let algorithm = get_algorithm();

            let result = provider.implementation.derive_key_from_password(
                password,
                &short_salt,
                algorithm,
                DEFAULT_KDF,
            );

            assert!(result.is_err(), "Deriving key with short salt should fail");
            let e = result.unwrap_err();
            assert!(matches!(e.error_kind(), CalErrorKind::BadParameter { .. }));
            assert!(
                e.to_string().contains("Wrong salt length."),
                "Incorrect error message for short salt: {}",
                e
            );
        }

        #[test]
        fn test_long_salt_length_fails() {
            let provider = setup_provider();
            let password = "test_password";
            let long_salt = [0u8; 65];
            let algorithm = get_algorithm();

            let result = provider.implementation.derive_key_from_password(
                password,
                &long_salt,
                algorithm,
                DEFAULT_KDF,
            );

            assert!(result.is_err(), "Deriving key with long salt should fail");
            let e = result.unwrap_err();
            assert!(matches!(e.error_kind(), CalErrorKind::BadParameter { .. }));
            assert!(
                e.to_string().contains("Wrong salt length."),
                "Incorrect error message for long salt: {}",
                e
            );
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
                DEFAULT_KDF,
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

    mod misc {
        use super::*;

        use std::sync::LazyLock;

        use color_eyre::eyre::{Ok, Result};

        use crate::tests::{setup, TestStore};

        static STORE: LazyLock<TestStore> = LazyLock::new(|| TestStore::new());

        const PROVIDER: LazyLock<Provider> = LazyLock::new(|| {
            create_provider_from_name("SoftwareProvider", STORE.impl_config().clone()).unwrap()
        });

        #[test]
        fn test_hash() -> Result<()> {
            setup();

            let data: Vec<u8> = (0..64).collect();
            let hash = PROVIDER.hash(&data, CryptoHash::Sha2_256)?;
            let hash2 = PROVIDER.hash(&data, CryptoHash::Sha2_256)?;

            assert!(hash.len() > 0);
            assert_eq!(hash, hash2);

            Ok(())
        }
    }
}

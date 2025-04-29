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
        use crate::tests::setup;
        use crate::{storage::StorageManager, tests::TestStore};
        use color_eyre::eyre::{eyre, Result};
        use nanoid::nanoid;
        use std::str::from_utf8;
        use std::sync::LazyLock;
        use tracing::instrument;

        static mut STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

        #[test]
        #[instrument]
        fn test_dh_exchange_client_server_keys() -> Result<()> {
            setup();

            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })?
                .ok_or_else(|| eyre!("StorageManager creation returned None"))?,
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
                )?;

                // Server creates an instance of SoftwareDHExchange
                let mut server_exchange = SoftwareDHExchange::new(
                    "key_id_server".to_string(),
                    storage_manager.clone(),
                    key_pair_spec,
                )?;

                // Client gets its public key
                let client_public_key = client_exchange.get_public_key()?;

                // Server gets its public key
                let server_public_key = server_exchange.get_public_key()?;

                // Client computes session keys using server's public key
                let (client_rx, client_tx) =
                    client_exchange.derive_client_session_keys(&server_public_key)?;

                // Server computes session keys using client's public key
                let (server_rx, server_tx) =
                    server_exchange.derive_server_session_keys(&client_public_key)?;

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
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_dh_exchange_encrypt_decrypt() -> Result<()> {
            setup();
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })?
                .ok_or_else(|| eyre!("StorageManager creation returned None"))?,
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
                )?;

                // Server creates an instance of SoftwareDHExchange
                let mut server_exchange = SoftwareDHExchange::new(
                    "key_id_server".to_string(),
                    storage_manager.clone(),
                    key_pair_spec,
                )?;

                // Get public keys
                let client_public_key = client_exchange.get_public_key()?;

                let server_public_key = server_exchange.get_public_key()?;

                // Derive session keys
                let (client_rx, client_tx) =
                    client_exchange.derive_client_session_keys(&server_public_key)?;

                let (server_rx, server_tx) =
                    server_exchange.derive_server_session_keys(&client_public_key)?;

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
                let (encrypted_data, iv) = client_tx_key_handle.encrypt_data(plaintext, &[])?;

                // Server decrypts with their rx key
                let decrypted_data = server_rx_key_handle.decrypt_data(&encrypted_data, &iv)?;

                assert_eq!(
                    from_utf8(&decrypted_data)?,
                    from_utf8(plaintext)?,
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
                let (server_encrypted, iv) =
                    server_tx_key_handle.encrypt_data(server_plaintext, &[])?;

                // Client decrypts with their rx key
                let client_decrypted = client_rx_key_handle.decrypt_data(&server_encrypted, &iv)?;

                assert_eq!(
                    from_utf8(&client_decrypted)?,
                    from_utf8(server_plaintext)?,
                    "Server-to-client decrypted data does not match plaintext"
                );
            }

            Ok(())
        }

        #[test]
        #[instrument]
        fn test_dh_exchange_with_invalid_public_key() -> Result<()> {
            setup();
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })?
                .ok_or_else(|| eyre!("StorageManager creation returned None"))?,
            );

            // Client creates an instance of SoftwareDHExchange
            let mut client_exchange = SoftwareDHExchange::new(
                "key_id_client".to_string(),
                storage_manager,
                KeyPairSpec::default(),
            )?;

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
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_dh_exchange_reuse() -> Result<()> {
            setup();
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })?
                .ok_or_else(|| eyre!("StorageManager creation returned None"))?,
            );

            // Client creates an instance of SoftwareDHExchange
            let mut client_exchange = SoftwareDHExchange::new(
                "key_id_client".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )?;

            let mut client_exchange2 = client_exchange.clone();

            // Generate two different server public keys
            let server_exchange1 = SoftwareDHExchange::new(
                "key_id_server1".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )?;
            let server_exchange2 = SoftwareDHExchange::new(
                "key_id_server2".to_string(),
                storage_manager,
                KeyPairSpec::default(),
            )?;

            let server_public_key1 = server_exchange1.get_public_key()?;
            let server_public_key2 = server_exchange2.get_public_key()?;

            // Client derives session keys with first server
            let (rx1, tx1) = client_exchange.derive_client_session_keys(&server_public_key1)?;

            // Client derives keys with second server - this should work fine with your implementation
            let (rx2, tx2) = client_exchange2.derive_client_session_keys(&server_public_key2)?;

            // Keys should be different when derived with different peer public keys
            assert_ne!(rx1, rx2, "Keys should be different with different peers");
            assert_ne!(tx1, tx2, "Keys should be different with different peers");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_multiple_key_derivations() -> Result<()> {
            setup();
            let storage_manager = Some(
                StorageManager::new("SoftwareProvider".to_owned(), unsafe {
                    &STORE.impl_config().additional_config
                })?
                .ok_or_else(|| eyre!("StorageManager creation returned None"))?,
            );

            // Client1 creates an instance of SoftwareDHExchange
            let mut client1_exchange = SoftwareDHExchange::new(
                "key_id_client1".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )?;

            // Client2 creates an instance of SoftwareDHExchange
            let mut client2_exchange = SoftwareDHExchange::new(
                "key_id_client2".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )?;

            // Server instances for each client
            let mut server_for_client1 = SoftwareDHExchange::new(
                "key_id_server_for_client1".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )?;
            let mut server_for_client2 = SoftwareDHExchange::new(
                "key_id_server_for_client2".to_string(),
                storage_manager.clone(),
                KeyPairSpec::default(),
            )?;

            // Get public keys
            let client1_public_key = client1_exchange.get_public_key()?;
            let client2_public_key = client2_exchange.get_public_key()?;
            let server1_public_key = server_for_client1.get_public_key()?;
            let server2_public_key = server_for_client2.get_public_key()?;

            // Derive keys for Client1 and Server1
            let (client1_rx, client1_tx) =
                client1_exchange.derive_client_session_keys(&server1_public_key)?;

            let (server1_rx, server1_tx) =
                server_for_client1.derive_server_session_keys(&client1_public_key)?;

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
            let (client2_rx, client2_tx) =
                client2_exchange.derive_client_session_keys(&server2_public_key)?;

            let (server2_rx, server2_tx) =
                server_for_client2.derive_server_session_keys(&client2_public_key)?;

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
            Ok(())
        }
    }

    mod derive_key {
        use super::*;
        use std::sync::LazyLock;

        use crate::{
            common::traits::{key_handle::KeyHandleImpl, module_provider::ProviderImpl},
            tests::{setup, TestStore},
        };
        use color_eyre::eyre::Result;
        use tracing::instrument;

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
        #[instrument]
        fn test_successful_key_derivation() -> Result<()> {
            setup();
            let provider = setup_provider();
            let password = "test_password";
            let salt = [0u8; 16];
            let algorithm = get_algorithm();

            let key_handle_result: Result<KeyHandle, CalError> = provider
                .implementation
                .derive_key_from_password(password, &salt, algorithm, DEFAULT_KDF);
            assert!(key_handle_result.is_ok(), "Failed to derive key");

            let key_handle = key_handle_result?;
            let key = key_handle.implementation.extract_key()?;
            assert_eq!(key.len(), 32, "Derived key should be 32 bytes");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_different_passwords_yield_different_keys() -> Result<()> {
            setup();
            let provider = setup_provider();
            let salt = [0u8; 16];
            let algorithm = get_algorithm();

            let key1 = provider
                .implementation
                .derive_key_from_password("test_password", &salt, algorithm, DEFAULT_KDF)?
                .implementation
                .extract_key()?;

            let key2 = provider
                .implementation
                .derive_key_from_password("another_password", &salt, algorithm, DEFAULT_KDF)?
                .implementation
                .extract_key()?;

            assert_ne!(
                key1, key2,
                "Different passwords should yield different keys"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_different_salts_yield_different_keys() -> Result<()> {
            setup();
            let provider = setup_provider();
            let password = "test_password";
            let algorithm = get_algorithm();

            let key1 = provider
                .implementation
                .derive_key_from_password(password, &[0u8; 16], algorithm, DEFAULT_KDF)?
                .implementation
                .extract_key()?;

            let key2 = provider
                .implementation
                .derive_key_from_password(password, &[1u8; 16], algorithm, DEFAULT_KDF)?
                .implementation
                .extract_key()?;

            assert_ne!(key1, key2, "Different salts should yield different keys");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_short_salt_length_fails() -> Result<()> {
            setup();
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

            Ok(())
        }

        #[test]
        #[instrument]
        fn test_long_salt_length_fails() -> Result<()> {
            setup();
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

            Ok(())
        }

        #[test]
        #[instrument]
        fn test_argon2i_variant() -> Result<()> {
            setup();

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
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_get_random() -> Result<()> {
            setup();
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
            Ok(())
        }
    }

    #[allow(clippy::borrow_interior_mutable_const)]
    #[allow(clippy::declare_interior_mutable_const)]
    mod misc {
        use super::*;

        use std::sync::LazyLock;

        use color_eyre::eyre::{Ok, Result};
        use tracing::instrument;

        use crate::tests::{setup, TestStore};

        static STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

        const PROVIDER: LazyLock<Provider> = LazyLock::new(|| {
            create_provider_from_name("SoftwareProvider", STORE.impl_config().clone()).unwrap()
        });

        #[test]
        #[instrument]
        fn test_hash() -> Result<()> {
            setup();

            let data: Vec<u8> = (0..64).collect();
            let hash = PROVIDER.hash(&data, CryptoHash::Sha2_256)?;
            let hash2 = PROVIDER.hash(&data, CryptoHash::Sha2_256)?;

            assert!(!hash.is_empty());
            assert_eq!(hash, hash2);

            Ok(())
        }
    }
}

#[allow(static_mut_refs)]
#[cfg(test)]
mod tests {
    use crate::common::{
        config::{KeyPairSpec, KeySpec},
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher},
            hashes::CryptoHash,
        },
        error::CalError,
        factory, KeyHandle, KeyPairHandle,
    };
    use ring::rand::{SecureRandom, SystemRandom};
    use std::str::from_utf8;

    mod key_pair_handle {
        use super::*;
        use crate::{common::Provider, tests::TestStore};

        static mut STORE: std::sync::LazyLock<TestStore> = std::sync::LazyLock::new(TestStore::new);

        /// Helper function to create a new key pair and extract the `SoftwareKeyPairHandle`
        fn create_key_pair_handle(spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider: Provider =
                factory::create_provider_from_name("SoftwareProvider", impl_config).unwrap();

            provider.create_key_pair(spec)
        }

        #[test]
        fn test_sign_and_verify() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec).unwrap();

            let data = b"Data to sign";

            // Sign the data
            let signature = software_key_pair_handle
                .sign_data(data)
                .expect("Signing failed");

            // Verify the signature
            let verified = software_key_pair_handle
                .verify_signature(data, &signature)
                .expect("Verification failed");

            assert!(verified, "Signature should be valid");
        }

        #[test]
        fn test_verify_with_wrong_data() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec).unwrap();

            let data = b"Data to sign";
            let wrong_data = b"Wrong data";

            // Sign the data
            let signature = software_key_pair_handle
                .sign_data(data)
                .expect("Signing failed");

            // Attempt to verify the signature with wrong data
            let verified = software_key_pair_handle
                .verify_signature(wrong_data, &signature)
                .expect("Verification failed");

            assert!(
                !verified,
                "Signature verification should fail with wrong data"
            );
        }

        #[test]
        fn test_verify_with_wrong_key() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            // Create two key pairs
            let software_key_pair_handle1 = create_key_pair_handle(spec).unwrap();
            let software_key_pair_handle2 = create_key_pair_handle(spec).unwrap();

            let data = b"Data to sign";

            // Sign the data with the first key pair
            let signature = software_key_pair_handle1
                .sign_data(data)
                .expect("Signing failed");

            // Attempt to verify the signature with the second key pair
            let verified = software_key_pair_handle2
                .verify_signature(data, &signature)
                .expect("Verification failed");

            assert!(
                !verified,
                "Signature verification should fail with wrong key"
            );
        }

        #[test]
        fn test_get_public_key() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec).unwrap();

            // Get the public key
            let public_key = software_key_pair_handle
                .get_public_key()
                .expect("Failed to get public key");

            assert!(!public_key.is_empty(), "Public key should not be empty");
        }

        #[test]
        fn test_sign_with_public_only_key() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider: Provider =
                factory::create_provider_from_name("SoftwareProvider", impl_config).unwrap();

            let key_pair_handle = provider.create_key_pair(spec).unwrap();

            // Get the public key
            let public_key = key_pair_handle
                .get_public_key()
                .expect("Failed to get public key");

            // Create a public-only key pair handle

            let public_only_key_pair_handle = provider
                .import_public_key(spec, &public_key)
                .expect("Failed to create public-only key pair handle");

            let data = b"Data to sign";

            // Attempt to sign data with public-only key pair handle
            let sign_result = public_only_key_pair_handle.sign_data(data);

            assert!(
                sign_result.is_err(),
                "Signing should fail with public-only key"
            );
        }

        #[test]
        fn test_verify_with_public_only_key() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider: Provider =
                factory::create_provider_from_name("SoftwareProvider", impl_config).unwrap();

            let key_pair_handle = provider.create_key_pair(spec).unwrap();

            // Get the public key
            let public_key = key_pair_handle
                .get_public_key()
                .expect("Failed to get public key");

            let public_only_key_pair_handle = provider
                .import_public_key(spec, &public_key)
                .expect("Failed to create public-only key pair handle");

            let data = b"Data to sign";

            // Sign the data with the original key pair
            let signature = key_pair_handle.sign_data(data).expect("Signing failed");

            // Verify the signature with the public-only key pair handle
            let verified = public_only_key_pair_handle
                .verify_signature(data, &signature)
                .expect("Verification failed");

            assert!(verified, "Signature should be valid with public-only key");
        }

        #[test]
        fn test_id_method() {
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec).unwrap();

            // Get the key ID
            let key_id = software_key_pair_handle.id().unwrap();

            assert!(!key_id.is_empty(), "Key ID should not be empty");
        }
    }
    mod key_handle {
        use crate::tests::TestStore;

        use super::*;

        static mut STORE: std::sync::LazyLock<TestStore> = std::sync::LazyLock::new(TestStore::new);

        /// Helper function to create a new key and extract the `SoftwareKeyHandle`
        fn create_software_key_handle(spec: KeySpec) -> Result<KeyHandle, CalError> {
            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider =
                factory::create_provider_from_name("SoftwareProvider", impl_config).unwrap();
            provider.create_key(spec)
        }

        #[test]
        fn test_encrypt_decrypt_data() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext = b"Test data for encryption and decryption via provider.";

            let encrypted_data = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            assert_ne!(
                encrypted_data.0, plaintext,
                "Encrypted data should not match plaintext"
            );

            let decrypted_data = software_key_handle
                .decrypt_data(&encrypted_data.0, &[])
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data).unwrap(),
                from_utf8(plaintext).unwrap(),
                "Decrypted data does not match original plaintext"
            );
        }

        #[test]
        fn test_encrypt_decrypt_empty_data() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext: &[u8] = &[];

            let encrypted_data = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let decrypted_data = software_key_handle
                .decrypt_data(&encrypted_data.0, &[])
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data).unwrap(),
                from_utf8(plaintext).unwrap(),
                "Decrypted data does not match original plaintext"
            );
        }

        #[test]
        fn test_decrypt_with_wrong_key() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle1 = create_software_key_handle(spec).unwrap();
            let software_key_handle2 = create_software_key_handle(spec).unwrap();

            let plaintext = b"Data encrypted with key 1";

            let encrypted_data = software_key_handle1
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let decrypted_result = software_key_handle2.decrypt_data(&encrypted_data.0, &[]);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with wrong key"
            );
        }

        #[test]
        fn test_decrypt_modified_ciphertext() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext = b"Data to encrypt and then tamper with.";

            let mut encrypted_data = software_key_handle
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            encrypted_data.0[15] ^= 0xFF;

            let decrypted_result = software_key_handle.decrypt_data(&encrypted_data.0, &[]);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with tampered ciphertext"
            );
        }

        #[test]
        fn test_id_method() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let key_id = software_key_handle.id().unwrap();

            assert!(!key_id.is_empty(), "Key ID should not be empty");
        }

        #[test]
        fn wtest_encrypt_decrypt_large_data() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let plaintext = vec![0x61; 1_048_576]; // 1 MB of data

            let encrypted_data = software_key_handle
                .encrypt_data(&plaintext)
                .expect("Encryption failed");

            let decrypted_data = software_key_handle
                .decrypt_data(&encrypted_data.0, &[])
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&plaintext).unwrap(),
                from_utf8(&decrypted_data).unwrap(),
                "Decrypted data does not match original plaintext"
            );
        }

        #[test]
        fn test_encrypt_same_plaintext_multiple_times() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm128,
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
                .decrypt_data(&encrypted_data1.0, &[])
                .expect("Decryption failed");

            let decrypted_data2 = software_key_handle
                .decrypt_data(&encrypted_data2.0, &[])
                .expect("Decryption failed");

            assert_eq!(
                from_utf8(&decrypted_data1).unwrap(),
                from_utf8(plaintext).unwrap(),
                "First decrypted data does not match plaintext"
            );
            assert_eq!(
                from_utf8(&decrypted_data2).unwrap(),
                from_utf8(plaintext).unwrap(),
                "Second decrypted data does not match plaintext"
            );
        }

        #[test]
        fn test_decrypt_random_data() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let mut random_data = vec![0u8; 50];
            let rng = SystemRandom::new();
            rng.fill(&mut random_data).unwrap();

            let decrypted_result = software_key_handle.decrypt_data(&random_data, &[]);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with random data"
            );
        }

        #[test]
        fn test_decrypt_short_data() {
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec).unwrap();

            let short_data = vec![0u8; 10];

            let decrypted_result = software_key_handle.decrypt_data(&short_data, &[]);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with insufficient data"
            );
        }

        #[test]
        fn test_encrypt_decrypt_different_cipher_spec() {
            let spec256 = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let spec128 = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle256 = create_software_key_handle(spec256).unwrap();
            let software_key_handle128 = create_software_key_handle(spec128).unwrap();

            let plaintext = b"Testing encryption with different cipher specs";

            let encrypted_data = software_key_handle256
                .encrypt_data(plaintext)
                .expect("Encryption failed");

            let decrypted_result = software_key_handle128.decrypt_data(&encrypted_data.0, &[]);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with different cipher spec"
            );
        }

        #[test]
        fn test_encrypt_decrypt_multiple_keys() {
            let specs = vec![
                KeySpec {
                    cipher: Cipher::AesGcm128,
                    ..Default::default()
                },
                KeySpec {
                    cipher: Cipher::AesGcm256,
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
                    .decrypt_data(&encrypted_data.0, &[])
                    .expect("Decryption failed");

                assert_eq!(
                    from_utf8(&decrypted_data).unwrap(),
                    from_utf8(plaintext).unwrap(),
                    "Decrypted data does not match plaintext"
                );
            }
        }
    }
}

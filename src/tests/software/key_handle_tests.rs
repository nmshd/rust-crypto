#[allow(static_mut_refs)]
#[cfg(test)]
mod tests {
    use tracing::instrument;

    use crate::common::{
        config::{KeyPairSpec, KeySpec},
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher},
            hashes::CryptoHash,
        },
        error::CalError,
        factory, KeyHandle, KeyPairHandle,
    };
    use crate::tests::setup;
    use color_eyre::eyre::Result;
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
                factory::create_provider_from_name("SoftwareProvider", impl_config)
                    .expect("Failed initializing SoftwareProvider");

            provider.create_key_pair(spec)
        }

        #[test]
        #[instrument]
        fn test_sign_and_verify() -> Result<()> {
            setup();

            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec)?;

            let data = b"Data to sign";

            // Sign the data
            let signature = software_key_pair_handle.sign_data(data)?;

            // Verify the signature
            let verified = software_key_pair_handle.verify_signature(data, &signature)?;

            assert!(verified, "Signature should be valid");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_verify_with_wrong_data() -> Result<()> {
            setup();
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec)?;

            let data = b"Data to sign";
            let wrong_data = b"Wrong data";

            // Sign the data
            let signature = software_key_pair_handle.sign_data(data)?;

            // Attempt to verify the signature with wrong data
            let verified = software_key_pair_handle.verify_signature(wrong_data, &signature)?;

            assert!(
                !verified,
                "Signature verification should fail with wrong data"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_verify_with_wrong_key() -> Result<()> {
            setup();
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            // Create two key pairs
            let software_key_pair_handle1 = create_key_pair_handle(spec)?;
            let software_key_pair_handle2 = create_key_pair_handle(spec)?;

            let data = b"Data to sign";

            // Sign the data with the first key pair
            let signature = software_key_pair_handle1.sign_data(data)?;

            // Attempt to verify the signature with the second key pair
            let verified = software_key_pair_handle2.verify_signature(data, &signature)?;

            assert!(
                !verified,
                "Signature verification should fail with wrong key"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_get_public_key() -> Result<()> {
            setup();
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec)?;

            // Get the public key
            let public_key = software_key_pair_handle.get_public_key()?;

            assert!(!public_key.is_empty(), "Public key should not be empty");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_sign_with_public_only_key() -> Result<()> {
            setup();
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider: Provider =
                factory::create_provider_from_name("SoftwareProvider", impl_config)
                    .expect("Failed initializing SoftwareProvider");

            let key_pair_handle = provider.create_key_pair(spec)?;

            // Get the public key
            let public_key = key_pair_handle.get_public_key()?;

            // Create a public-only key pair handle

            let public_only_key_pair_handle = provider.import_public_key(spec, &public_key)?;

            let data = b"Data to sign";

            // Attempt to sign data with public-only key pair handle
            let sign_result = public_only_key_pair_handle.sign_data(data);

            assert!(
                sign_result.is_err(),
                "Signing should fail with public-only key"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_verify_with_public_only_key() -> Result<()> {
            setup();
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider: Provider =
                factory::create_provider_from_name("SoftwareProvider", impl_config)
                    .expect("Failed initializing SoftwareProvider");

            let key_pair_handle = provider.create_key_pair(spec)?;

            // Get the public key
            let public_key = key_pair_handle.get_public_key()?;

            let public_only_key_pair_handle = provider.import_public_key(spec, &public_key)?;

            let data = b"Data to sign";

            // Sign the data with the original key pair
            let signature = key_pair_handle.sign_data(data)?;

            // Verify the signature with the public-only key pair handle
            let verified = public_only_key_pair_handle.verify_signature(data, &signature)?;

            assert!(verified, "Signature should be valid with public-only key");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_id_method() -> Result<()> {
            setup();
            // Define a KeyPairSpec for ECDSA with P256 curve
            let spec = KeyPairSpec {
                asym_spec: AsymmetricKeySpec::P256,
                cipher: None,
                signing_hash: CryptoHash::Sha2_256,
                ephemeral: true,
                non_exportable: false,
            };

            // Create a new key pair and get the SoftwareKeyPairHandle
            let software_key_pair_handle = create_key_pair_handle(spec)?;

            // Get the key ID
            let key_id = software_key_pair_handle.id()?;

            assert!(!key_id.is_empty(), "Key ID should not be empty");
            Ok(())
        }
    }
    mod key_handle {
        use crate::tests::TestStore;

        use super::*;

        static mut STORE: std::sync::LazyLock<TestStore> = std::sync::LazyLock::new(TestStore::new);

        /// Helper function to create a new key and extract the `SoftwareKeyHandle`
        fn create_software_key_handle(spec: KeySpec) -> Result<KeyHandle, CalError> {
            let impl_config = unsafe { STORE.impl_config().clone() };

            let mut provider = factory::create_provider_from_name("SoftwareProvider", impl_config)
                .expect("Failed initializing SoftwareProvider");
            provider.create_key(spec)
        }

        #[test]
        #[instrument]
        fn test_encrypt_decrypt_data() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let plaintext = b"Test data for encryption and decryption via provider.";

            let encrypted_data = software_key_handle.encrypt_data(plaintext)?;

            assert_ne!(
                encrypted_data.0, plaintext,
                "Encrypted data should not match plaintext"
            );

            let decrypted_data =
                software_key_handle.decrypt_data(&encrypted_data.0, &encrypted_data.1)?;

            assert_eq!(
                from_utf8(&decrypted_data)?,
                from_utf8(plaintext)?,
                "Decrypted data does not match original plaintext"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_encrypt_decrypt_empty_data() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let plaintext: &[u8] = &[];

            let encrypted_data = software_key_handle.encrypt_data(plaintext)?;

            let decrypted_data =
                software_key_handle.decrypt_data(&encrypted_data.0, &encrypted_data.1)?;

            assert_eq!(
                from_utf8(&decrypted_data)?,
                from_utf8(plaintext)?,
                "Decrypted data does not match original plaintext"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_decrypt_with_wrong_key() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle1 = create_software_key_handle(spec)?;
            let software_key_handle2 = create_software_key_handle(spec)?;

            let plaintext = b"Data encrypted with key 1";

            let encrypted_data = software_key_handle1.encrypt_data(plaintext)?;

            let decrypted_result =
                software_key_handle2.decrypt_data(&encrypted_data.0, &encrypted_data.1);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with wrong key"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_decrypt_modified_ciphertext() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let plaintext = b"Data to encrypt and then tamper with.";

            let mut encrypted_data = software_key_handle.encrypt_data(plaintext)?;

            encrypted_data.0[15] ^= 0xFF;

            let decrypted_result =
                software_key_handle.decrypt_data(&encrypted_data.0, &encrypted_data.1);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with tampered ciphertext"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_id_method() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let key_id = software_key_handle.id()?;

            assert!(!key_id.is_empty(), "Key ID should not be empty");
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_encrypt_decrypt_large_data() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let plaintext = vec![0x61; 1_048_576]; // 1 MB of data

            let encrypted_data = software_key_handle.encrypt_data(&plaintext)?;

            let decrypted_data =
                software_key_handle.decrypt_data(&encrypted_data.0, &encrypted_data.1)?;

            assert_eq!(
                from_utf8(&plaintext)?,
                from_utf8(&decrypted_data)?,
                "Decrypted data does not match original plaintext"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_encrypt_same_plaintext_multiple_times() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let plaintext = b"Same plaintext encrypted multiple times";

            let encrypted_data1 = software_key_handle.encrypt_data(plaintext)?;

            let encrypted_data2 = software_key_handle.encrypt_data(plaintext)?;

            assert_ne!(
                encrypted_data1, encrypted_data2,
                "Encrypted data should differ with different nonces"
            );

            let decrypted_data1 =
                software_key_handle.decrypt_data(&encrypted_data1.0, &encrypted_data1.1)?;

            let decrypted_data2 =
                software_key_handle.decrypt_data(&encrypted_data2.0, &encrypted_data2.1)?;

            assert_eq!(
                from_utf8(&decrypted_data1)?,
                from_utf8(plaintext)?,
                "First decrypted data does not match plaintext"
            );
            assert_eq!(
                from_utf8(&decrypted_data2)?,
                from_utf8(plaintext)?,
                "Second decrypted data does not match plaintext"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_decrypt_random_data() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let mut random_data = vec![0u8; 50];
            let mut nonce = vec![0u8; 12];
            let rng = SystemRandom::new();
            rng.fill(&mut random_data).unwrap();
            rng.fill(&mut nonce).unwrap();

            let decrypted_result = software_key_handle.decrypt_data(&random_data, &nonce);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with random data"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_decrypt_short_data() -> Result<()> {
            setup();
            let spec = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let software_key_handle = create_software_key_handle(spec)?;

            let short_data = vec![0u8; 10];

            let decrypted_result = software_key_handle.decrypt_data(&short_data, &[]);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with insufficient data"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_encrypt_decrypt_different_cipher_spec() -> Result<()> {
            setup();
            let spec256 = KeySpec {
                cipher: Cipher::AesGcm256,
                ..Default::default()
            };

            let spec128 = KeySpec {
                cipher: Cipher::AesGcm128,
                ..Default::default()
            };

            let software_key_handle256 = create_software_key_handle(spec256)?;
            let software_key_handle128 = create_software_key_handle(spec128)?;

            let plaintext = b"Testing encryption with different cipher specs";

            let encrypted_data = software_key_handle256.encrypt_data(plaintext)?;

            let decrypted_result =
                software_key_handle128.decrypt_data(&encrypted_data.0, &encrypted_data.1);

            assert!(
                decrypted_result.is_err(),
                "Decryption should fail with different cipher spec"
            );
            Ok(())
        }

        #[test]
        #[instrument]
        fn test_encrypt_decrypt_multiple_keys() -> Result<()> {
            setup();
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
                let software_key_handle = create_software_key_handle(spec)?;

                let encrypted_data = software_key_handle.encrypt_data(plaintext)?;

                let decrypted_data =
                    software_key_handle.decrypt_data(&encrypted_data.0, &encrypted_data.1)?;

                assert_eq!(
                    from_utf8(&decrypted_data)?,
                    from_utf8(plaintext)?,
                    "Decrypted data does not match plaintext"
                );
            }
            Ok(())
        }
    }
}

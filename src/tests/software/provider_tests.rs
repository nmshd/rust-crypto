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
            traits::key_handle::{KeyHandleImpl, KeyHandleImplEnum},
            KeyHandle, Provider,
        },
        software::{key_handle::SoftwareKeyHandle, SoftwareProvider},
    };
    use ring::rand::{SecureRandom, SystemRandom};
    use std::str::from_utf8;
    use tempfile::Builder;

    fn create_software_key_handle(spec: KeySpec) -> Result<SoftwareKeyHandle, CalError> {
        let dir = Builder::new().prefix("metadata_test").tempdir().unwrap();
        let db_path = dir.path().join("metadata_test.db");
        let mut provider: Provider = factory::create_provider_from_name(
            "SoftwareProvider".to_owned(),
            SoftwareProvider::get_default_config(db_path.to_str()),
        )
        .unwrap();
        let key_handle = provider.create_key(spec)?;
        extract_software_key_handle(&key_handle)
    }

    fn extract_software_key_handle(key_handle: &KeyHandle) -> Result<SoftwareKeyHandle, CalError> {
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

    // fn trim_trailing_zeros(data: &[u8]) -> &[u8] {
    //     let end = data.iter().rposition(|&x| x != 0).map_or(0, |pos| pos + 1);
    //     &data[..end]
    // }

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

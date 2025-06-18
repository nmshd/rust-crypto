use std::sync::LazyLock;

use color_eyre::eyre::Result;
use rstest::{fixture, rstest};

use crate::prelude::{AdditionalConfig, KeySpec};
use crate::tests::{setup, CleanupKeyPair, TestStore};
use crate::{
    common::{
        config::KeyPairSpec,
        crypto::algorithms::{encryption::AsymmetricKeySpec, hashes::CryptoHash},
        factory::create_provider_from_name,
        Provider,
    },
    prelude::Cipher,
};

static STORE: LazyLock<TestStore> = LazyLock::new(|| TestStore::new());

#[test]
fn test_create_apple_secure_provider_from_name() -> Result<()> {
    setup();

    let _provider = create_provider_from_name("APPLE_SECURE_ENCLAVE", STORE.impl_config())
        .expect("Failed initializing apple secure provider.");

    Ok(())
}

#[test]
fn test_create_key_with_provider() -> Result<()> {
    setup();

    let mut provider = create_provider_from_name("APPLE_SECURE_ENCLAVE", STORE.impl_config())
        .expect("Failed initializing apple secure provider.");

    let key_spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::P256,
        cipher: None,
        signing_hash: CryptoHash::Sha2_256,
        ephemeral: false,
        non_exportable: true,
    };

    let _key = provider.create_key_pair(key_spec)?;

    let _key_cleanup = CleanupKeyPair::new(_key.clone());

    Ok(())
}

#[test]
fn test_create_key_pair_sign_and_verify_data() -> Result<()> {
    setup();

    let mut provider = create_provider_from_name("APPLE_SECURE_ENCLAVE", STORE.impl_config())
        .expect("Failed initializing apple secure provider.");

    let hashes = vec![
        CryptoHash::Sha2_224,
        CryptoHash::Sha2_256,
        CryptoHash::Sha2_384,
        CryptoHash::Sha2_512,
    ];

    for hash in hashes {
        let key_spec = KeyPairSpec {
            asym_spec: AsymmetricKeySpec::P256,
            cipher: None,
            signing_hash: hash,
            ephemeral: false,
            non_exportable: true,
        };

        let key = provider.create_key_pair(key_spec)?;
        let _key_cleanup = CleanupKeyPair::new(key.clone());

        let test_data = Vec::from(b"Hello World!");

        let signature = key.sign_data(&test_data)?;

        assert!(key.verify_signature(&test_data, &signature)?);
    }

    Ok(())
}

#[test]
fn test_load_key_pair() -> Result<()> {
    setup();

    let id;
    let _key_cleanup;
    {
        let mut provider = create_provider_from_name("APPLE_SECURE_ENCLAVE", STORE.impl_config())
            .expect("Failed initializing apple secure provider.");

        let key_spec = KeyPairSpec {
            asym_spec: AsymmetricKeySpec::P256,
            cipher: None,
            signing_hash: CryptoHash::Sha2_256,
            ephemeral: false,
            non_exportable: true,
        };

        let key = provider.create_key_pair(key_spec)?;
        _key_cleanup = CleanupKeyPair::new(key.clone());

        id = key.id()?;
    }

    let mut provider = create_provider_from_name("APPLE_SECURE_ENCLAVE", STORE.impl_config())
        .expect("Failed initializing apple secure provider.");

    let key = provider.load_key_pair(id.clone())?;

    assert_eq!(id, key.id()?);

    Ok(())
}

#[fixture]
fn provider() -> Provider {
    create_provider_from_name("APPLE_SECURE_ENCLAVE", STORE.impl_config())
        .expect("Failed initializing apple secure provider.")
}

fn spec_from_cipher_hash(cipher: Option<Cipher>, hash: CryptoHash) -> KeyPairSpec {
    KeyPairSpec {
        asym_spec: AsymmetricKeySpec::P256,
        cipher: cipher,
        signing_hash: hash,
        ephemeral: false,
        non_exportable: true,
    }
}

#[rstest]
#[case::sha224_aesgcm128(spec_from_cipher_hash(Some(Cipher::AesGcm128), CryptoHash::Sha2_224))]
#[case::sha256_aesgcm256(spec_from_cipher_hash(Some(Cipher::AesGcm256), CryptoHash::Sha2_256))]
#[case::sha512_aesgcm256(spec_from_cipher_hash(Some(Cipher::AesGcm256), CryptoHash::Sha2_512))]
#[should_panic]
#[case::sha3256_aesgcm128(spec_from_cipher_hash(Some(Cipher::AesGcm128), CryptoHash::Sha3_256))]
#[case::sha224_nocipher(spec_from_cipher_hash(None, CryptoHash::Sha2_224))]
#[case::sha224_aescbc128(spec_from_cipher_hash(Some(Cipher::AesCbc128), CryptoHash::Sha2_224))]
fn test_encrypt_data(mut provider: Provider, #[case] spec: KeyPairSpec) {
    setup();

    let key = provider.create_key_pair(spec).unwrap();

    let test_data = b"TEST DATA".to_vec();

    let test_encrypt_data = key.encrypt_data(&test_data).unwrap();

    let decrypted_data = key.decrypt_data(&test_encrypt_data).unwrap();

    assert_eq!(test_data, decrypted_data);
}

fn test_secured_software_provider(mut provider: Provider) -> Result<()> {
    let spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::P256,
        cipher: Some(Cipher::AesGcm256),
        signing_hash: CryptoHash::Sha2_512,
        ephemeral: false,
        non_exportable: true,
    };

    let key = provider.create_key_pair(spec)?;

    let mut provider_impl_config = STORE.impl_config();
    provider_impl_config.additional_config.extend(vec![
        AdditionalConfig::StorageConfigDSA(key.clone()),
        AdditionalConfig::StorageConfigAsymmetricEncryption(key),
    ]);

    let test_data = b"TEST DATA".to_vec();

    let id;
    let ciphertext;

    {
        let mut software_provider =
            create_provider_from_name("SoftwareProvider", provider_impl_config.clone()).unwrap();

        let symmetric_spec = KeySpec {
            cipher: Cipher::AesGcm256,
            signing_hash: CryptoHash::Sha2_256,
            ephemeral: false,
            non_exportable: true,
        };

        let software_key = software_provider.create_key(symmetric_spec)?;
        ciphertext = software_key.encrypt(&test_data)?;
        id = software_key.id()?;
    }

    {
        let mut software_provider =
            create_provider_from_name("SoftwareProvider", STORE.impl_config()).unwrap();

        let _cal_error = software_provider.load_key(id.clone()).unwrap_err();
    }

    {
        let mut software_provider =
            create_provider_from_name("SoftwareProvider", provider_impl_config).unwrap();

        let software_key = software_provider.load_key(id)?;
        let decrypted_data = software_key.decrypt_data(&ciphertext.0, &ciphertext.1)?;

        assert_eq!(decrypted_data, test_data);
    }

    Ok(())
}

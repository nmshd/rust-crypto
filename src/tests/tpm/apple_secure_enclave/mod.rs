use std::sync::LazyLock;

use color_eyre::eyre::Result;

use crate::common::{
    config::KeyPairSpec,
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, EccCurve, EccSigningScheme},
        hashes::{CryptoHash, Sha2Bits},
    },
    factory::create_provider_from_name,
};
use crate::tests::{setup, CleanupKeyPair, TestStore};

static STORE: LazyLock<TestStore> = LazyLock::new(|| TestStore::new());

#[test]
fn test_create_apple_secure_provider_from_name() -> Result<()> {
    setup();

    let _provider =
        create_provider_from_name("APPLE_SECURE_ENCLAVE".to_owned(), STORE.impl_config())
            .expect("Failed initializing apple secure provider.");

    Ok(())
}

#[test]
fn test_create_key_with_provider() -> Result<()> {
    setup();

    let mut provider =
        create_provider_from_name("APPLE_SECURE_ENCLAVE".to_owned(), STORE.impl_config())
            .expect("Failed initializing apple secure provider.");

    let key_spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Ecc {
            scheme: EccSigningScheme::EcDsa,
            curve: EccCurve::P256,
        },
        cipher: None,
        signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
    };

    let _key = provider.create_key_pair(key_spec)?;

    let _key_cleanup = CleanupKeyPair::new(_key.clone());

    Ok(())
}

#[test]
fn test_create_key_pair_sign_and_verify_data() -> Result<()> {
    setup();

    let mut provider =
        create_provider_from_name("APPLE_SECURE_ENCLAVE".to_owned(), STORE.impl_config())
            .expect("Failed initializing apple secure provider.");

    let hashes = vec![
        CryptoHash::Sha2(Sha2Bits::Sha224),
        CryptoHash::Sha2(Sha2Bits::Sha256),
        CryptoHash::Sha2(Sha2Bits::Sha384),
        CryptoHash::Sha2(Sha2Bits::Sha512),
    ];

    for hash in hashes {
        let key_spec = KeyPairSpec {
            asym_spec: AsymmetricKeySpec::Ecc {
                scheme: EccSigningScheme::EcDsa,
                curve: EccCurve::P256,
            },
            cipher: None,
            signing_hash: hash,
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
        let mut provider =
            create_provider_from_name("APPLE_SECURE_ENCLAVE".to_owned(), STORE.impl_config())
                .expect("Failed initializing apple secure provider.");

        let key_spec = KeyPairSpec {
            asym_spec: AsymmetricKeySpec::Ecc {
                scheme: EccSigningScheme::EcDsa,
                curve: EccCurve::P256,
            },
            cipher: None,
            signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
        };

        let key = provider.create_key_pair(key_spec)?;
        _key_cleanup = CleanupKeyPair::new(key.clone());

        id = key.id()?;
    }

    let mut provider =
        create_provider_from_name("APPLE_SECURE_ENCLAVE".to_owned(), STORE.impl_config())
            .expect("Failed initializing apple secure provider.");

    let key = provider.load_key_pair(id.clone())?;

    assert_eq!(id, key.id()?);

    Ok(())
}

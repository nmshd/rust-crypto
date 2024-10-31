use crate::common::{
    config::{KeyPairSpec, ProviderImplConfig},
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, EccCurve, EccSigningScheme},
        hashes::{CryptoHash, Sha2Bits},
    },
    error::CalError,
    factory::create_provider_from_name,
};
use crate::tests::CleanupKeyPair;

#[test]
fn test_create_apple_secure_provider_from_name() {
    let _provider = create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    )
    .expect("Failed initializing apple secure provider.");
}

#[test]
fn test_create_key_with_provider() -> Result<(), CalError> {
    let mut provider = create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    )
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
fn test_create_key_pair_sign_and_verify_data() -> Result<(), CalError> {
    let mut provider = create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    )
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
    let _key_cleanup = CleanupKeyPair::new(key.clone());

    let test_data = Vec::from(b"Hello World!");

    let signature = key.sign_data(&test_data)?;

    assert!(key.verify_signature(&test_data, &signature)?);

    Ok(())
}

#[test]
fn test_load_key_pair() -> Result<(), CalError> {
    let id;
    let _key_cleanup;
    {
        let mut provider = create_provider_from_name(
            "APPLE_SECURE_ENCLAVE".to_owned(),
            ProviderImplConfig::AppleSecureEnclave {},
        )
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

    let mut provider = create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    )
    .expect("Failed initializing apple secure provider.");

    let key = provider.load_key_pair(id.clone())?;

    assert_eq!(id, key.id()?);

    Ok(())
}

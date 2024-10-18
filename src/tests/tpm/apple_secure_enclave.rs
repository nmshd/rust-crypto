use async_std::task::block_on;

use crate::common::{
    config::{KeyPairSpec, ProviderImplConfig},
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, EccCurve, EccSigningScheme},
        hashes::{CryptoHash, Sha2Bits},
    },
    error::SecurityModuleError,
    factory::create_provider_from_name,
    KeyPairHandle, Provider,
};

#[test]
fn test_create_apple_secure_provider_from_name() {
    let provider = block_on(create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    ))
    .expect("Failed initializing apple secure provider.");
}

#[test]
fn test_create_key_with_provider() -> Result<(), SecurityModuleError> {
    let mut provider = block_on(create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    ))
    .expect("Failed initializing apple secure provider.");

    let key_spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Ecc {
            scheme: EccSigningScheme::EcDsa,
            curve: EccCurve::P256,
        },
        cipher: None,
        signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
    };

    let key = block_on(provider.create_key_pair(key_spec))?;

    Ok(())
}

#[test]
fn test_create_key_pair_sign_and_verify_data() -> Result<(), SecurityModuleError> {
    let mut provider = block_on(create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    ))
    .expect("Failed initializing apple secure provider.");

    let key_spec = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::Ecc {
            scheme: EccSigningScheme::EcDsa,
            curve: EccCurve::P256,
        },
        cipher: None,
        signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
    };

    let key = block_on(provider.create_key_pair(key_spec))?;

    let test_data = Vec::from(b"Hello World!");

    let signature = block_on(key.sign_data(test_data.clone()))?;

    assert!(block_on(key.verify_signature(test_data, signature))?);

    Ok(())
}

#[test]
fn test_load_key_pair() -> Result<(), SecurityModuleError> {
    let id;
    {
        let mut provider = block_on(create_provider_from_name(
            "APPLE_SECURE_ENCLAVE".to_owned(),
            ProviderImplConfig::AppleSecureEnclave {},
        ))
        .expect("Failed initializing apple secure provider.");

        let key_spec = KeyPairSpec {
            asym_spec: AsymmetricKeySpec::Ecc {
                scheme: EccSigningScheme::EcDsa,
                curve: EccCurve::P256,
            },
            cipher: None,
            signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
        };

        let key = block_on(provider.create_key_pair(key_spec))?;

        id = key.id()?;
    }

    let mut provider = block_on(create_provider_from_name(
        "APPLE_SECURE_ENCLAVE".to_owned(),
        ProviderImplConfig::AppleSecureEnclave {},
    ))
    .expect("Failed initializing apple secure provider.");

    let key = block_on(provider.load_key_pair(id.clone()))?;

    assert_eq!(id, key.id()?);

    Ok(())
}

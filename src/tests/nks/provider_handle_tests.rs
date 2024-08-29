use std::sync::Arc;

use async_std::task::block_on;

use crate::{
    common::{
        crypto::algorithms::{encryption::SymmetricMode, hashes::Sha2Bits, KeyBits},
        traits::module_provider_config::ProviderConfig,
    },
    nks::NksConfig,
    tpm::TpmConfig,
};
#[allow(unused_imports)]
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
                hashes::Hash,
            },
            KeyUsage,
        },
        traits::module_provider::Provider,
    },
    tpm::win::TpmProvider,
};

#[test]
fn test_create_rsa_key() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let config = TpmConfig::new(
        Some(AsymmetricEncryption::Rsa(KeyBits::Bits2048)),
        Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
        Some(Hash::Sha2(Sha2Bits::Sha256)),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ]
        .into(),
    );

    block_on(provider.initialize_module()).expect("Failed to initialize module");
    block_on(provider.create_key("test_rsa_key", config)).expect("Failed to create RSA key");
}

#[test]
fn test_create_ecdsa_key() {
    let mut provider = TpmProvider::new("test_ecdsa_key".to_string());

    let config = TpmConfig::new(
        Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
            EccCurves::Curve25519,
        ))),
        Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
        Some(Hash::Sha2(Sha2Bits::Sha256)),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ]
        .into(),
    );

    block_on(provider.initialize_module()).expect("Failed to initialize module");
    block_on(provider.create_key("test_ecdsa_key", config)).expect("Failed to create ECDSA key");
}

#[test]
fn test_create_ecdh_key() {
    let mut provider = TpmProvider::new("test_ecdh_key".to_string());

    let config = TpmConfig::new(
        Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(
            EccCurves::Curve25519,
        ))),
        Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
        Some(Hash::Sha2(Sha2Bits::Sha256)),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt].into(),
    );
    block_on(provider.initialize_module()).expect("Failed to initialize module");
    block_on(provider.create_key("test_ecdh_key", config)).expect("Failed to create ECDH key");
}

#[test]
fn test_load_rsa_key() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let config = TpmConfig::new(
        Some(AsymmetricEncryption::Rsa(KeyBits::Bits4096)),
        Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
        Some(Hash::Sha2(Sha2Bits::Sha256)),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ]
        .into(),
    );

    block_on(provider.initialize_module()).expect("Failed to initialize module");
    block_on(provider.load_key("test_rsa_key", config)).expect("Failed to load RSA key");
}

#[test]
fn test_load_ecdsa_key() {
    let mut provider = TpmProvider::new("test_ecdsa_key".to_string());

    let config = TpmConfig::new(
        Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
            EccCurves::Curve25519,
        ))),
        Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
        Some(Hash::Sha2(Sha2Bits::Sha256)),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ]
        .into(),
    );

    block_on(provider.initialize_module()).expect("Failed to initialize module");
    block_on(provider.load_key("test_ecdsa_key", config)).expect("Failed to load ECDSA key");
}

#[test]
fn test_load_ecdh_key() {
    let mut provider = TpmProvider::new("test_ecdh_key".to_string());

    let config = TpmConfig::new(
        Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(
            EccCurves::Curve25519,
        ))),
        Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
        Some(Hash::Sha2(Sha2Bits::Sha256)),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt].into(),
    );

    block_on(provider.initialize_module()).expect("Failed to initialize module");
    block_on(provider.load_key("test_ecdh_key", config)).expect("Failed to load ECDH key");
}

/// Returns a configuration object for the NksProvider based on the provided key type.
///
/// This function creates a new NksConfig object with predefined settings for the
/// asymmetric encryption algorithm, hash algorithm, and key usages. The specific settings
/// are determined by the `key_type` parameter.
///
/// # Arguments
///
/// * `key_type` - A string slice that specifies the type of the key. The accepted values are "rsa", "ecdsa", and "ecdh".
///
/// # Returns
///
/// An `Option` that, on success, contains an `Arc` to a `ProviderConfig` object. If the `key_type` is not recognized, it returns `None`.
///
/// # Example
///
/// ```
// let config = get_config("rsa").unwrap();
/// ```
pub fn get_config(
    key_type: &str,
    key_size: Option<KeyBits>,
    aes_mode: Option<SymmetricMode>,
) -> Option<Arc<dyn ProviderConfig + Send + Sync>> {
    match key_type {
        "rsa" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Rsa(2048.into())),
            Hash::Sha2(256.into()),
            vec![
                KeyUsage::ClientAuth,
                KeyUsage::Decrypt,
                KeyUsage::SignEncrypt,
                KeyUsage::CreateX509,
            ],
            None,
        )),
        "ecdsa" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
                EccCurves::Curve25519,
            ))),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
            None,
        )),
        "ecdh" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(
                EccCurves::Curve25519,
            ))),
            Hash::Sha2(384.into()),
            vec![KeyUsage::Decrypt],
            None,
        )),
        "aes" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            let aes_mode = aes_mode.unwrap_or(SymmetricMode::Gcm); // Default to GCM mode if no mode is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(aes_mode, key_size)),
            ))
        }
        _ => None,
    }
}

use std::sync::Arc;
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, EccCurves, EccSchemeAlgorithm},
                hashes::Hash,
            },
            KeyUsage,
        },
        traits::module_provider::Provider,
    },
    nks::hcvault::NksProvider,
};
use crate::common::crypto::algorithms::encryption::{BlockCiphers, SymmetricMode};
use crate::common::crypto::algorithms::hashes::Sha2Bits;
use crate::common::crypto::algorithms::KeyBits;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::nks::NksConfig;

#[test]
fn test_create_rsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa", None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .create_key("test_rsa_key", Box::new(nks_config.clone()))
            .expect("Failed to create RSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

#[test]
fn test_create_ecdsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdsa", None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .create_key("test_ecdsa_key", Box::new(nks_config.clone()))
            .expect("Failed to create ECDSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

#[test]
fn test_create_ecdh_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdh", None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .create_key("test_ecdh_key", Box::new(nks_config.clone()))
            .expect("Failed to create ECDH key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

#[test]
fn test_create_aes_key() {
    for &key_size in &[KeyBits::Bits128, KeyBits::Bits192, KeyBits::Bits256] {
        for &aes_mode in &["aes_gcm", "aes_ccm", "aes_ecb", "aes_cbc", "aes_ctr", "aes_cfb"] {
            let mut provider = NksProvider::new("test_key".to_string());

            provider.config = Some(get_config(aes_mode, Some(key_size)).unwrap());

            provider
                .initialize_module()
                .expect("Failed to initialize module");

            if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
                provider
                    .create_key(&format!("test_{}_key_{}", aes_mode, key_size as u8), Box::new(nks_config.clone()))
                    .expect("Failed to create AES key");
            } else {
                println!("Failed to downcast to NksConfig");
            }
        }
    }
}

#[test]
fn test_load_rsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa", None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_rsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load RSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

#[test]
fn test_load_ecdsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdsa", None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_ecdsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load ECDSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

#[test]
fn test_load_ecdh_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("ecdh", None).unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_ecdh_key", Box::new(nks_config.clone()))
            .expect("Failed to load ECDH key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
}

#[test]
fn test_load_aes_key() {
    for &key_size in &[KeyBits::Bits128, KeyBits::Bits192, KeyBits::Bits256] {
        for &aes_mode in &["aes_gcm", "aes_ccm", "aes_ecb", "aes_cbc", "aes_ctr", "aes_cfb"] {
            let mut provider = NksProvider::new("test_key".to_string());

            provider.config = Some(get_config(aes_mode, Some(key_size)).unwrap());

            provider
                .initialize_module()
                .expect("Failed to initialize module");

            if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
                provider
                    .load_key(&format!("test_{}_key_{}", aes_mode, key_size as u8), Box::new(nks_config.clone()))
                    .expect("Failed to load AES key");
            } else {
                println!("Failed to downcast to NksConfig");
            }
        }
    }
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
/// let config = get_config("rsa").unwrap();
/// ```
pub fn get_config(key_type: &str, key_size: Option<KeyBits>) -> Option<Arc<dyn ProviderConfig + Send + Sync>> {
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
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519))),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
            None,
        )),
        "ecdh" => Some(NksConfig::new(
            "".to_string(),
            "https://localhost:5000/".to_string(),
            Option::from(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519))),
            Hash::Sha2(384.into()),
            vec![KeyUsage::Decrypt],
            None,
        )),
        "aes_gcm" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(SymmetricMode::Gcm, key_size)),
            ))
        },
        "aes_ccm" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(SymmetricMode::Ccm, key_size)),
            ))
        },
        "aes_ecb" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(SymmetricMode::Ecb, key_size)),
            ))
        },
        "aes_cbc" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(SymmetricMode::Cbc, key_size)),
            ))
        },
        "aes_ctr" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(SymmetricMode::Ctr, key_size)),
            ))
        },
        "aes_cfb" => {
            let key_size = key_size.unwrap_or(KeyBits::Bits256); // Default to 256 bits if no size is provided
            Some(NksConfig::new(
                "".to_string(),
                "https://localhost:5000/".to_string(),
                None,
                Hash::Sha2(256.into()),
                vec![KeyUsage::Decrypt],
                Some(BlockCiphers::Aes(SymmetricMode::Cfb, key_size)),
            ))
        },
        _ => None,
    }
}

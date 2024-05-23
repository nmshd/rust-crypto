use std::sync::Arc;
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
                hashes::Hash,
            },
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::{key_handle::KeyHandle, module_provider::Provider}
    },
    nks::hcvault::NksProvider,
};
use crate::common::crypto::algorithms::hashes::Sha2Bits;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::nks::NksConfig;


#[test]
fn do_nothing() {
    assert_eq!(1, 1);
}

#[test]
fn test_initialize_module() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa").unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    println!("{:?}", provider);
}

#[test]
fn test_create_rsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa").unwrap());

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

    provider.config = Some(get_config("ecdsa").unwrap());

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

    provider.config = Some(get_config("ecdh").unwrap());

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
fn test_load_rsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(get_config("rsa").unwrap());

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

    provider.config = Some(get_config("ecdsa").unwrap());

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

    provider.config = Some(get_config("ecdh").unwrap());

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
fn get_config(key_type: &str) -> Option<Arc<dyn ProviderConfig+Send+Sync>> {
    match key_type {
        "rsa" => Some(NksConfig::new(
            "".to_string(),
            "http://localhost:5272/apidemo/".to_string(),
            AsymmetricEncryption::Rsa(2048.into()),
            Hash::Sha2(256.into()),
            vec![
                KeyUsage::ClientAuth,
                KeyUsage::Decrypt,
                KeyUsage::SignEncrypt,
                KeyUsage::CreateX509,
            ]
        )),
        "ecdsa" => Some(NksConfig::new(
            "".to_string(),
            "http://localhost:5272/apidemo/".to_string(),
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)),
            Hash::Sha2(Sha2Bits::Sha256),
            vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
        )),
        "ecdh" => Some(NksConfig::new(
            "".to_string(),
            "http://localhost:5272/apidemo/".to_string(),
            AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
            Hash::Sha2(384.into()),
            vec![KeyUsage::Decrypt],
        )),
        _ => None,
    }
}

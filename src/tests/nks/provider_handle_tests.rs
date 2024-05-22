use std::path::Path;
use std::str::FromStr;
use futures::future::ok;
use reqwest::Url;
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
        error::SecurityModuleError,
        traits::{key_handle::KeyHandle, module_provider::Provider}
    },
    nks::hcvault::NksProvider,
};
use crate::common::crypto::algorithms::encryption::SymmetricMode;
use crate::common::crypto::algorithms::hashes::Sha2Bits;
use crate::common::crypto::algorithms::KeyBits;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::nks::NksConfig;


#[test]
fn do_nothing() {
    assert_eq!(1, 1);
}

#[test]
fn test_initialize_module() {
    let mut provider = NksProvider::new("test_key".to_string());

    //set config
    let config= NksConfig::new(
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
    );
    provider.config = Some(config);

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    println!("{:?}", provider);
    ok::<(), ()>(());
}

#[test]
fn test_create_rsa_key() {
    let mut provider = NksProvider::new("test_key".to_string());

    //set config
    let config= NksConfig::new(
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
    );
    provider.config = Some(config);

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

    //set config
    let config= NksConfig::new(
        "".to_string(),
        "http://localhost:5272/apidemo/".to_string(),
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
    );
    provider.config = Some(config);

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

    //set config
    let config= NksConfig::new(
        "".to_string(),
        "http://localhost:5272/apidemo/".to_string(),
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        Hash::Sha2(384.into()),
        vec![KeyUsage::Decrypt],
    );
    provider.config = Some(config);

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

// #[test]
// fn test_load_rsa_key() {
//     let mut provider = NksProvider::new("test_key".to_string());
//
//     let key_algorithm = AsymmetricEncryption::Rsa(2048.into());
//     let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
//     let hash = Some(Hash::Sha2(256.into()));
//     let key_usages = vec![
//         KeyUsage::ClientAuth,
//         KeyUsage::Decrypt,
//         KeyUsage::SignEncrypt,
//         KeyUsage::CreateX509,
//     ];
//
//     provider
//         .initialize_module(999999,999999, key_algorithm.clone(), sym_algorithm.clone(), hash.clone(), key_usages.clone())
//         .expect("Failed to initialize module");
//
//     provider
//         .load_key("test_rsa_key")
//         .expect("Failed to load RSA key");
// }
//
// #[test]
// fn test_load_ecdsa_key() {
//     let mut provider = NksProvider::new("test_key".to_string());
//
//     let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519));
//     let sym_algorithm = None;
//     let hash = Some(Hash::Sha2(256.into()));
//     let key_usages = vec![KeyUsage::ClientAuth, KeyUsage::SignEncrypt];
//
//     provider
//         .initialize_module(999999,999999, key_algorithm.clone(), sym_algorithm.clone(), hash.clone(), key_usages.clone())
//         .expect("Failed to initialize module");
//
//     provider
//         .load_key("test_ecdsa_key")
//         .expect("Failed to load ECDSA key");
// }
//
// #[test]
// fn test_load_ecdh_key() {
//     let mut provider = NksProvider::new("test_key".to_string());
//
//     let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519));
//     let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
//     let hash = Some(Hash::Sha2(384.into()));
//     let key_usages = vec![KeyUsage::Decrypt];
//
//     provider
//         .initialize_module(999999,999999, key_algorithm.clone(), sym_algorithm.clone(), hash.clone(), key_usages.clone())
//         .expect("Failed to initialize module");
//     provider
//         .load_key("test_ecdh_key")
//         .expect("Failed to load ECDH key");
// }

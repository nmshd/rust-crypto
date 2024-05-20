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


#[test]
fn do_nothing() {
    assert_eq!(1, 1);
}

#[test]
fn test_initialize_module() {
    let mut provider = NksProvider::new("test_key".to_string());

    let key_algorithm = AsymmetricEncryption::Rsa(2048.into());
    let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
    let hash = Some(Hash::Sha2(256.into()));
    let key_usages = vec![
        KeyUsage::ClientAuth,
        KeyUsage::Decrypt,
        KeyUsage::SignEncrypt,
        KeyUsage::CreateX509,
    ];

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    println!("{:?}", provider);
}

// #[tokio::test]
// async fn test_create_rsa_key() {
//     let mut provider = NksProvider::new("test_key".to_string());
//     let token = provider.get_token(false).await.expect("Failed to get token");
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
//     provider
//         .create_key("test_rsa_key", key_algorithm.clone(), sym_algorithm.clone(), hash, key_usages)
//         .expect("Failed to create RSA key");
// }
// #[test]
// fn test_create_ecdsa_key() {
//     let mut provider = NksProvider::new("test_key".to_string());
//
//     let config = NksConfig::new(
//         AsymmetricEncryption::Rsa(KeyBits::Bits4096),
//         BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
//         Hash::Sha2(Sha2Bits::Sha256),
//         vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
//     );
//
//     provider
//         .initialize_module()
//         .expect("Failed to initialize module");
//     provider
//         .create_key("test_ecdsa_key", config)
//         .expect("Failed to create ECDSA key");
// }
//
// #[test]
// fn test_create_ecdh_key() {
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
//         .create_key("test_ecdh_key", key_algorithm.clone(), sym_algorithm.clone(), hash, key_usages)
//         .expect("Failed to create ECDH key");
// }
//
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

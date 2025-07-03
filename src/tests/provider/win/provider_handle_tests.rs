// use async_std::task::block_on;

// use crate::{
//     common::crypto::algorithms::{encryption::SymmetricMode, hashes::Sha2Bits, KeyBits},
//     tpm::TpmConfig,
// };
// #[allow(unused_imports)]
// use crate::{
//     common::{
//         crypto::{
//             algorithms::{
//                 encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
//                 hashes::Hash,
//             },
//             KeyUsage,
//         },
//         traits::module_provider::Provider,
//     },
//     tpm::win::TpmProvider,
// };

// #[test]
// fn test_create_rsa_key() {
//     let mut provider = TpmProvider::new("test_rsa_key".to_string());

//     let config = TpmConfig::new(
//         Some(AsymmetricEncryption::Rsa(KeyBits::Bits2048)),
//         Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
//         Some(Hash::Sha2(Sha2Bits::Sha256)),
//         vec![
//             KeyUsage::SignEncrypt,
//             KeyUsage::ClientAuth,
//             KeyUsage::Decrypt,
//             KeyUsage::CreateX509,
//         ]
//         .into(),
//     );

//     block_on(provider.initialize_module()).expect("Failed to initialize module");
//     block_on(provider.create_key("test_rsa_key", config)).expect("Failed to create RSA key");
// }

// #[test]
// fn test_create_ecdsa_key() {
//     let mut provider = TpmProvider::new("test_ecdsa_key".to_string());

//     let config = TpmConfig::new(
//         Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
//             EccCurves::Curve25519,
//         ))),
//         Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
//         Some(Hash::Sha2(Sha2Bits::Sha256)),
//         vec![
//             KeyUsage::SignEncrypt,
//             KeyUsage::ClientAuth,
//             KeyUsage::Decrypt,
//             KeyUsage::CreateX509,
//         ]
//         .into(),
//     );

//     block_on(provider.initialize_module()).expect("Failed to initialize module");
//     block_on(provider.create_key("test_ecdsa_key", config)).expect("Failed to create ECDSA key");
// }

// #[test]
// fn test_create_ecdh_key() {
//     let mut provider = TpmProvider::new("test_ecdh_key".to_string());

//     let config = TpmConfig::new(
//         Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(
//             EccCurves::Curve25519,
//         ))),
//         Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
//         Some(Hash::Sha2(Sha2Bits::Sha256)),
//         vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt].into(),
//     );
//     block_on(provider.initialize_module()).expect("Failed to initialize module");
//     block_on(provider.create_key("test_ecdh_key", config)).expect("Failed to create ECDH key");
// }

// #[test]
// fn test_load_rsa_key() {
//     let mut provider = TpmProvider::new("test_rsa_key".to_string());

//     let config = TpmConfig::new(
//         Some(AsymmetricEncryption::Rsa(KeyBits::Bits4096)),
//         Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
//         Some(Hash::Sha2(Sha2Bits::Sha256)),
//         vec![
//             KeyUsage::SignEncrypt,
//             KeyUsage::ClientAuth,
//             KeyUsage::Decrypt,
//             KeyUsage::CreateX509,
//         ]
//         .into(),
//     );

//     block_on(provider.initialize_module()).expect("Failed to initialize module");
//     block_on(provider.load_key("test_rsa_key", config)).expect("Failed to load RSA key");
// }

// #[test]
// fn test_load_ecdsa_key() {
//     let mut provider = TpmProvider::new("test_ecdsa_key".to_string());

//     let config = TpmConfig::new(
//         Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
//             EccCurves::Curve25519,
//         ))),
//         Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
//         Some(Hash::Sha2(Sha2Bits::Sha256)),
//         vec![
//             KeyUsage::SignEncrypt,
//             KeyUsage::ClientAuth,
//             KeyUsage::Decrypt,
//             KeyUsage::CreateX509,
//         ]
//         .into(),
//     );

//     block_on(provider.initialize_module()).expect("Failed to initialize module");
//     block_on(provider.load_key("test_ecdsa_key", config)).expect("Failed to load ECDSA key");
// }

// #[test]
// fn test_load_ecdh_key() {
//     let mut provider = TpmProvider::new("test_ecdh_key".to_string());

//     let config = TpmConfig::new(
//         Some(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(
//             EccCurves::Curve25519,
//         ))),
//         Some(BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512)),
//         Some(Hash::Sha2(Sha2Bits::Sha256)),
//         vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt].into(),
//     );

//     block_on(provider.initialize_module()).expect("Failed to initialize module");
//     block_on(provider.load_key("test_ecdh_key", config)).expect("Failed to load ECDH key");
// }

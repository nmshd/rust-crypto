use crate::{
    common::crypto::algorithms::{encryption::SymmetricMode, hashes::Sha2Bits, KeyBits},
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
    tpm::linux::TpmProvider,
};

#[test]
fn test_create_rsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");
}

#[test]
fn test_create_ecdsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecdsa_key", config)
        .expect("Failed to create ECDSA key");
}

#[test]
fn test_create_ecdh_key() {
    let mut provider = TpmProvider::new("test_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
        ],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecdh_key", config)
        .expect("Failed to create ECDH key");
}

#[test]
fn test_load_rsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
            KeyUsage::CreateX509,
        ],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    provider
        .load_key("test_rsa_key", config)
        .expect("Failed to load RSA key");
}

#[test]
fn test_load_ecdsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    provider
        .load_key("test_ecdsa_key", config)
        .expect("Failed to load ECDSA key");
}

#[test]
fn test_load_ecdh_key() {
    let mut provider = TpmProvider::new("test_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![
            KeyUsage::SignEncrypt,
            KeyUsage::ClientAuth,
            KeyUsage::Decrypt,
        ],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_ecdh_key", config)
        .expect("Failed to load ECDH key");
}

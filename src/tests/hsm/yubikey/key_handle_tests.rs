#[cfg(test)]
#[allow(unused_imports)]
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
            hashes::Hash,
        },
        KeyUsage,
    },
    traits::{key_handle::KeyHandle, module_provider::Provider},
};

use crate::hsm::{yubikey::YubiKeyProvider, HsmProviderConfig};

#[test]
fn test_sign_and_verify_rsa_2048() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(crate::common::crypto::algorithms::KeyBits::Bits2048),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

#[test]
fn test_sign_and_verify_ecc_256() {
    let mut provider = YubiKeyProvider::new("test_ecc_key".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P256)),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecc_key", config)
        .expect("Failed to create ECDSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

#[test]
fn test_sign_and_verify_ecc_384() {
    let mut provider = YubiKeyProvider::new("test_ecc_key".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::P384)),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecc_key", config)
        .expect("Failed to create ECDSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}
/*
#[test]
fn test_encrypt_and_decrypt_rsa() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}

#[test]
fn test_encrypt_and_decrypt_ecdh() {
    let mut provider = TpmProvider::new("test_ecdh_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecdh_key", config)
        .expect("Failed to create ECDH key");

    let data = b"Hello, World!";
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}
*/

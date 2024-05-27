#[cfg(test)]
use crate::common::crypto::algorithms::{encryption::SymmetricMode, hashes::Sha2Bits, KeyBits};
#[allow(unused_imports)]
use crate::{common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
            hashes::Hash,
        },
        KeyUsage,
    },
    traits::{key_handle::KeyHandle, module_provider::Provider},
}, hsm::yubikey::YubiKeyProvider,
};
#[test]
fn test_create_rsa_key() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());

    provider
        .initialize_module("Rsa", KeyUsage::SignEncrypt)
        .expect("Failed to initialize module");
    provider.create_key().expect("Failed to create RSA key");
}

#[test]
fn test_create_ecc_key() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());

    provider
        .initialize_module("Ecc", KeyUsage::SignEncrypt)
        .expect("Failed to initialize module");
    provider.create_key().expect("Failed to create RSA key");
}

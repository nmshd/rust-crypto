#[allow(unused_imports)]
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
            hashes::Hash,
            KeyBits,
        },
        KeyUsage,
    },
    traits::module_provider::Provider,
};
use crate::hsm::yubikey::YubiKeyProvider;
use crate::hsm::HsmProviderConfig;

#[cfg(feature = "yubi")]
#[test]
fn test_create_rsa_key_1024() {
    let key_id = "test_rsa_key";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits1024),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key(key_id, config)
        .expect("Failed to create RSA key");
}

#[cfg(feature = "yubi")]
#[test]
fn test_create_rsa_key_2048() {
    let key_id = "test_rsa_key";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits2048),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key(key_id, config)
        .expect("Failed to create RSA key");
}

#[cfg(feature = "yubi")]
#[test]
fn test_create_ecc_key_256() {
    let key_id = "test_ecc_key";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)),
        vec![KeyUsage::SignEncrypt],
    );
    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key(key_id, config)
        .expect("Failed to create ECC key");
}

#[cfg(feature = "yubi")]
#[test]
fn test_create_ecc_key_384() {
    let key_id = "test_ecc_key";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P384)),
        vec![KeyUsage::SignEncrypt],
    );
    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key(key_id, config)
        .expect("Failed to create ECC key");
}

#[test]
fn test_load_rsa_key() {
    let key_id = "test_rsa_key";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits2048),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_rsa_key", config)
        .expect("Failed to load RSA key");
}

#[test]
fn test_load_ecc_key() {
    let key_id = "test_ecc_key";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .load_key("test_ecc_key", config)
        .expect("Failed to load ECC key");
}

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
    provider
        .initialize_module()
        .expect("Failed to initialize TPM module");

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
        .create_key(
            "test_rsa_key",
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        )
        .expect("Failed to create RSA key");
}

#[test]
fn test_create_ecdsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());
    provider
        .initialize_module()
        .expect("Failed to initialize TPM module");

    let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519));
    let sym_algorithm = None;
    let hash = Some(Hash::Sha2(256.into()));
    let key_usages = vec![KeyUsage::ClientAuth, KeyUsage::SignEncrypt];

    provider
        .create_key(
            "test_ecdsa_key",
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        )
        .expect("Failed to create ECDSA key");
}

#[test]
fn test_create_ecdh_key() {
    let mut provider = TpmProvider::new("test_key".to_string());
    provider
        .initialize_module()
        .expect("Failed to initialize TPM module");

    let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519));
    let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
    let hash = Some(Hash::Sha2(384.into()));
    let key_usages = vec![KeyUsage::Decrypt];

    provider
        .create_key(
            "test_ecdh_key",
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        )
        .expect("Failed to create ECDH key");
}

#[test]
fn test_load_rsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());
    provider
        .initialize_module()
        .expect("Failed to initialize TPM module");

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
        .create_key(
            "test_rsa_key",
            key_algorithm.clone(),
            sym_algorithm.clone(),
            hash.clone(),
            key_usages.clone(),
        )
        .expect("Failed to create RSA key");

    provider
        .load_key(
            "test_rsa_key",
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        )
        .expect("Failed to load RSA key");
}

#[test]
fn test_load_ecdsa_key() {
    let mut provider = TpmProvider::new("test_key".to_string());
    provider
        .initialize_module()
        .expect("Failed to initialize TPM module");

    let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519));
    let sym_algorithm = None;
    let hash = Some(Hash::Sha2(256.into()));
    let key_usages = vec![KeyUsage::ClientAuth, KeyUsage::SignEncrypt];

    provider
        .create_key(
            "test_ecdsa_key",
            key_algorithm.clone(),
            sym_algorithm.clone(),
            hash.clone(),
            key_usages.clone(),
        )
        .expect("Failed to create ECDSA key");

    provider
        .load_key(
            "test_ecdsa_key",
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        )
        .expect("Failed to load ECDSA key");
}

#[test]
fn test_load_ecdh_key() {
    let mut provider = TpmProvider::new("test_key".to_string());
    provider
        .initialize_module()
        .expect("Failed to initialize TPM module");

    let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519));
    let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
    let hash = Some(Hash::Sha2(384.into()));
    let key_usages = vec![KeyUsage::Decrypt];

    provider
        .create_key(
            "test_ecdh_key",
            key_algorithm.clone(),
            sym_algorithm.clone(),
            hash.clone(),
            key_usages.clone(),
        )
        .expect("Failed to create ECDH key");

    provider
        .load_key(
            "test_ecdh_key",
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        )
        .expect("Failed to load ECDH key");
}

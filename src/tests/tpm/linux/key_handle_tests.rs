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
        traits::{key_handle::KeyHandle, module_provider::Provider},
    },
    tpm::linux::TpmProvider,
};

#[test]
fn test_sign_and_verify_rsa() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let key_algorithm = AsymmetricEncryption::Rsa(2048.into());
    let sym_algorithm = None;
    let hash = Some(Hash::Sha2(256.into()));
    let key_usages = vec![KeyUsage::ClientAuth, KeyUsage::SignEncrypt];

    provider
        .initialize_module(key_algorithm, sym_algorithm, hash, key_usages)
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key")
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

#[test]
fn test_sign_and_verify_ecdsa() {
    let mut provider = TpmProvider::new("test_ecdsa_key".to_string());

    let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519));
    let sym_algorithm = None;
    let hash = Some(Hash::Sha2(256.into()));
    let key_usages = vec![KeyUsage::ClientAuth, KeyUsage::SignEncrypt];

    provider
        .initialize_module(key_algorithm, sym_algorithm, hash, key_usages)
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecdsa_key")
        .expect("Failed to create ECDSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

#[test]
fn test_encrypt_and_decrypt_rsa() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let key_algorithm = AsymmetricEncryption::Rsa(2048.into());
    let sym_algorithm = None;
    let hash = Some(Hash::Sha2(256.into()));
    let key_usages = vec![KeyUsage::Decrypt, KeyUsage::SignEncrypt];

    provider
        .initialize_module(key_algorithm, sym_algorithm, hash, key_usages)
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key")
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

    let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519));
    let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
    let hash = Some(Hash::Sha2(384.into()));
    let key_usages = vec![KeyUsage::Decrypt];

    provider
        .initialize_module(key_algorithm, sym_algorithm, hash, key_usages)
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecdh_key")
        .expect("Failed to create ECDH key");

    let data = b"Hello, World!";
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}

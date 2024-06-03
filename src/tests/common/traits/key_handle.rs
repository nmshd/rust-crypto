use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{
                    AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm,
                    SymmetricMode,
                },
                hashes::{Hash, Sha2Bits},
                KeyBits,
            },
            KeyUsage,
        },
        factory::SecurityModule,
    },
    hsm::core::instance::HsmType,
    tests::common::traits::setup_security_module,
    tpm::{core::instance::TpmType, TpmConfig},
};
use test_case::test_matrix;

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_sign_and_verify_rsa(module: SecurityModule) {
    let provider = setup_security_module(module);

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
    );

    provider
        .lock()
        .unwrap()
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .lock()
        .unwrap()
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let signature = provider
        .lock()
        .unwrap()
        .sign_data(data)
        .expect("Failed to sign data");

    assert!(provider
        .lock()
        .unwrap()
        .verify_signature(data, &signature)
        .unwrap());
}

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_sign_and_verify_ecdsa(module: SecurityModule) {
    let provider = setup_security_module(module);

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
    );

    provider
        .lock()
        .unwrap()
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .lock()
        .unwrap()
        .create_key("test_ecdsa_key", config)
        .expect("Failed to create ECDSA key");

    let data = b"Hello, World!";
    let signature = provider
        .lock()
        .unwrap()
        .sign_data(data)
        .expect("Failed to sign data");

    assert!(provider
        .lock()
        .unwrap()
        .verify_signature(data, &signature)
        .unwrap());
}

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_encrypt_and_decrypt_rsa(module: SecurityModule) {
    let provider = setup_security_module(module);

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::Decrypt, KeyUsage::SignEncrypt],
    );

    provider
        .lock()
        .unwrap()
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .lock()
        .unwrap()
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let encrypted_data = provider
        .lock()
        .unwrap()
        .encrypt_data(data)
        .expect("Failed to encrypt data");
    let decrypted_data = provider
        .lock()
        .unwrap()
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_encrypt_and_decrypt_ecdh(module: SecurityModule) {
    let provider = setup_security_module(module);

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt],
    );

    provider
        .lock()
        .unwrap()
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .lock()
        .unwrap()
        .create_key("test_ecdh_key", config)
        .expect("Failed to create ECDH key");

    let data = b"Hello, World!";
    let encrypted_data = provider
        .lock()
        .unwrap()
        .encrypt_data(data)
        .expect("Failed to encrypt data");
    let decrypted_data = provider
        .lock()
        .unwrap()
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}

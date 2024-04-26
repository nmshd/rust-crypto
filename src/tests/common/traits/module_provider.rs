use super::setup_security_module;
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, BlockCiphers},
                hashes::Hash,
            },
            KeyUsage,
        },
        factory::SecurityModule,
    },
    hsm::core::instance::HsmType,
    tpm::core::instance::TpmType,
};
use test_case::test_matrix;

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_create_rsa_key(module: SecurityModule) {
    let mut provider = setup_security_module(module);

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
        .initialize_module(key_algorithm, sym_algorithm, hash, key_usages)
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key")
        .expect("Failed to create RSA key")
}

#[test_matrix(
    [SecurityModule::Tpm(TpmType::Linux),
     SecurityModule::Tpm(TpmType::Windows),
     SecurityModule::Hsm(HsmType::NitroKey)]
)]
fn test_load_rsa_key(module: SecurityModule) {
    let mut provider = setup_security_module(module);

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
        .initialize_module(key_algorithm, sym_algorithm, hash, key_usages)
        .expect("Failed to initialize module");

    provider
        .load_key("test_rsa_key")
        .expect("Failed to load RSA key");
}

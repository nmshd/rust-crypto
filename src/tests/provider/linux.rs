use crate::{
    common::traits::module_provider::{ProviderFactory, ProviderImpl},
    prelude::{Cipher, KeySpec, ProviderImplConfig},
    provider::linux::provider_factory::LinuxProviderFactory,
    tests::setup,
};

use test_case::test_case;

#[test]
fn test_create_provider() {
    setup();
    let provider = LinuxProviderFactory {}.create_provider(ProviderImplConfig {
        additional_config: vec![],
    });

    provider.expect("provider should be created");
}

#[test]
fn test_create_key() {
    setup();
    let mut provider = LinuxProviderFactory {}
        .create_provider(ProviderImplConfig {
            additional_config: vec![],
        })
        .expect("provider should be created");

    provider
        .create_key(KeySpec {
            cipher: crate::prelude::Cipher::AesCbc256,
            signing_hash: crate::prelude::CryptoHash::Sha2_256,
            ephemeral: false,
            non_exportable: true,
        })
        .expect("key should be created");
}

#[test_case(100 ; "small data that does not need to be chunked")]
#[test_case(10000 ; "big data that needs to be chunked")]
fn test_encrypt(data_size: usize) {
    setup();
    let mut provider = LinuxProviderFactory {}
        .create_provider(ProviderImplConfig {
            additional_config: vec![],
        })
        .expect("provider should be created");

    let key = provider
        .create_key(KeySpec {
            cipher: crate::prelude::Cipher::AesCbc256,
            signing_hash: crate::prelude::CryptoHash::Sha2_256,
            ephemeral: false,
            non_exportable: true,
        })
        .expect("key should be created");

    let data = random_data(data_size);
    let iv = random_data(Cipher::AesCbc256.iv_len());

    let encrypted = key
        .encrypt_with_iv(&data, &iv)
        .expect("Should be able to encrypt");

    let decrypted = key
        .decrypt_data(&encrypted, &iv)
        .expect("Should be able to decrypt");

    assert_eq!(data, decrypted)
}

#[test_case(0 ; "empty iv should be generated")]
#[test_case(16 ; "iv with the right size should work")]
fn test_encrypt_iv(iv_size: usize) {
    setup();
    let mut provider = LinuxProviderFactory {}
        .create_provider(ProviderImplConfig {
            additional_config: vec![],
        })
        .expect("provider should be created");

    let key = provider
        .create_key(KeySpec {
            cipher: crate::prelude::Cipher::AesCbc256,
            signing_hash: crate::prelude::CryptoHash::Sha2_256,
            ephemeral: false,
            non_exportable: true,
        })
        .expect("key should be created");

    let data = random_data(100);
    let iv = random_data(iv_size);

    let (encrypted, iv) = key
        .encrypt_data(&data, &iv)
        .expect("Should be able to encrypt");

    let decrypted = key
        .decrypt_data(&encrypted, &iv)
        .expect("Should be able to decrypt");

    assert_eq!(data, decrypted)
}

fn random_data(len: usize) -> Vec<u8> {
    rand::random_iter().take(len).collect()
}

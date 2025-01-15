use std::collections::HashSet;

use crypto_layer::prelude::*;

fn main() {
    // ====== Creating the Provider ======

    // What algorithms does the provider need to support?
    // What security level (Software, Hardware) does the provider need to have?
    let capabilities = ProviderConfig {
        max_security_level: SecurityLevel::Software,
        min_security_level: SecurityLevel::Software,
        supported_ciphers: HashSet::from([]),
        supported_hashes: HashSet::from([CryptoHash::Sha2_256, CryptoHash::Sha2_512]),
        supported_asym_spec: HashSet::from([AsymmetricKeySpec::P256]),
    };

    // Providers need additional configuration.
    // All providers need either `FileStoreConfig` or `KVStoreConfig` for storing key metadata.
    let implementation_config = ProviderImplConfig {
        additional_config: vec![
            AdditionalConfig::FileStoreConfig {
                db_dir: "./testdb".to_owned(),
            },
            AdditionalConfig::StorageConfigPass("password".to_owned()),
        ],
    };

    let mut provider = create_provider(&capabilities, implementation_config).unwrap();

    println!("Provider: {}", provider.provider_name());

    // ====== Creating a Key Pair ======

    let key_pair_capabilities = KeyPairSpec {
        asym_spec: AsymmetricKeySpec::P256,
        cipher: None,
        signing_hash: CryptoHash::Sha2_512,
        ephemeral: false,
    };

    let key_pair_handle = provider.create_key_pair(key_pair_capabilities).unwrap();

    // The ID is used for loading the key again.
    let key_pair_id = key_pair_handle.id().unwrap();
    println!("KeyPairHandle ID: {}", key_pair_id);

    // ====== Signing and Verifying Data ======

    let data = b"Hello, world!";

    let signature = key_pair_handle.sign_data(data).unwrap();

    println!(
        "Verified: {}",
        key_pair_handle.verify_signature(data, &signature).unwrap()
    )
}

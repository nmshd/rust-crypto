use std::sync::Arc;
use serde_json::json;
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
   // tpm::linux::TpmProvider,
};
use crate::common::crypto::algorithms::encryption::SymmetricMode;
use crate::common::crypto::algorithms::hashes::Sha2Bits;
use crate::common::crypto::algorithms::KeyBits;
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::nks::hcvault::key_handle::add_signature_to_secrets;
use crate::nks::hcvault::NksProvider;
use crate::nks::NksConfig;
use crate::SecurityModuleError;

#[test]
fn do_nothing() {
    let mut provider = NksProvider::new("test_rsa_key".to_string());

    let config = NksConfig::new(
        "test_token".to_string(),
        "test_address".to_string(),
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::ClientAuth],
    );
    provider.config = Some(config);
    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        println!("NKS Token: {}", nks_config.nks_token);
        println!("NKS Address: {}", nks_config.nks_address);
    } else {
        println!("Failed to downcast to NksConfig");
    }
    assert_eq!(1, 1);
}

    #[test]
    fn test_sign_and_verify_rsa() {
        let mut provider = NksProvider::new("test_key".to_string());
        provider.config = Some(crate::tests::nks::provider_handle_tests::get_config("rsa").unwrap());
        provider
            .initialize_module()
            .expect("Failed to initialize module");

        if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
            provider
                .load_key("test_rsa_key", Box::new(nks_config.clone()))
                .expect("Failed to load RSA key");
        } else {
            println!("Failed to downcast to NksConfig");
        }
        let data = b"Hello, World!";
        let signature = provider.sign_data(data);
               let signature = provider.sign_data(data).expect(
            "Failed to sign data",
        );
        assert!(provider.verify_signature(data, &signature,).unwrap());
}

#[test]
fn test_sign_and_verify_ecdsa() {
    let mut provider = NksProvider::new("test_key".to_string());
    provider.config = Some(crate::tests::nks::provider_handle_tests::get_config("ecdsa").unwrap());
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_ecdsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load ECDSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
    let data = b"Hello, World!";
    let signature = provider.sign_data(data);
    let signature = provider.sign_data(data).expect(
        "Failed to sign data",
    );
    assert!(provider.verify_signature(data, &signature,).unwrap());
}

 #[test]
 fn test_encrypt_and_decrypt_rsa() {
    let mut provider = NksProvider::new("test_key".to_string());

    provider.config = Some(crate::tests::nks::provider_handle_tests::get_config("rsa").unwrap());

    provider
        .initialize_module()
        .expect("Failed to initialize module");

    if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
        provider
            .load_key("test_rsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load RSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }


     let data = b"Hello, World!";
     let original_length = data.len();
     let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
     let decrypted_data = provider
         .decrypt_data(&encrypted_data)
         .expect("Failed to decrypt data");
     let decrypted_data_without_padding: Vec<u8> = decrypted_data[0..original_length].to_vec();
       assert_eq!(data, decrypted_data_without_padding.as_slice())
}
//
// #[test]
// fn test_encrypt_and_decrypt_ecdh() {
//     let mut provider = NksProvider::new("test_ecdh_key".to_string());
//
//     let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519));
//     let sym_algorithm = Some(BlockCiphers::Aes(Default::default(), 256.into()));
//     let hash = Some(Hash::Sha2(384.into()));
//     let key_usages = vec![KeyUsage::Decrypt];
//
//     provider
//         .initialize_module(999999,999999, key_algorithm.clone(), sym_algorithm.clone(), hash.clone(), key_usages.clone())
//         .expect("Failed to initialize module");
//     provider
//         .create_key("test_rsa_key", key_algorithm.clone(), sym_algorithm.clone(), hash, key_usages)
//         .expect("Failed to create ECDH key");
//
//     let data = b"Hello, World!";
//     let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
//     let decrypted_data = provider
//         .decrypt_data(&encrypted_data)
//         .expect("Failed to decrypt data");
//
//     assert_eq!(data, decrypted_data.as_slice());
// }


#[test]
fn test_add_signature_to_secrets() {
    // Prepare the secrets JSON object
    let mut secrets_json = Some(json!({
        "data": {
            "signatures": []
        }
    }));

    // Prepare the signature
    let signature = vec![0, 1, 2, 3, 4, 5];

    // Prepare the ID and hash algorithm
    let id = "new_signature";
    let hash_algorithm = "SHA256";

    // Call the function
    let result = add_signature_to_secrets(secrets_json, signature, id, hash_algorithm);

    // Check the result
    match result {
        Ok(Some(updated_secrets_json)) => {
            // Check if the new signature was added
            let signatures = updated_secrets_json["data"]["signatures"].as_array().unwrap();
            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0]["id"], id);
            assert_eq!(signatures[0]["hashAlgorithm"], hash_algorithm);
        },
        Ok(None) => panic!("Function returned Ok(None)"),
        Err(SecurityModuleError::NksError) => panic!("Function returned an error"),
        _ => panic!("Unexpected result"),
    }
}
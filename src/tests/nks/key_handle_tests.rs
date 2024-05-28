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
use crate::nks::hcvault::NksProvider;
use crate::nks::NksConfig;
use crate::SecurityModuleError;

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

    let nks_config = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>().cloned();

    if let Some(nks_config) = nks_config {
        provider
            .load_key("test_ecdsa_key", Box::new(nks_config.clone()))
            .expect("Failed to load ECDSA key");
    } else {
        println!("Failed to downcast to NksConfig");
    }
    let data = b"Hello, World!";
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
     let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
     let decrypted_data = provider
         .decrypt_data(&encrypted_data)
         .expect("Failed to decrypt data");
       assert_eq!(data, decrypted_data.as_slice())
}

 #[test]
 fn test_encrypt_and_decrypt_ecdh() {
     let mut provider = NksProvider::new("ecdh".to_string());

     provider.config = Some(crate::tests::nks::provider_handle_tests::get_config("ecdh").unwrap());

     provider
         .initialize_module()
         .expect("Failed to initialize module");

     if let Some(nks_config) = provider.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
         provider
             .load_key("test_ecdh_key", Box::new(nks_config.clone()))
             .expect("Failed to load ecdh key");
     } else {
         println!("Failed to downcast to NksConfig");
     }


     let data = b"Hello, World!";
     let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
     let decrypted_data = provider
         .decrypt_data(&encrypted_data)
         .expect("Failed to decrypt data");
     assert_eq!(data, decrypted_data.as_slice())
 }

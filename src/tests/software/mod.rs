pub mod key_handle_tests;
pub mod provider_tests;
#[cfg(all(test, feature = "sodium-tests"))]
pub mod sodium_tests;

// use crate::{
//     common::{error::CalError, traits::module_provider::ProviderImpl, Provider},
//     prelude::ProviderImplConfig,
//     software::SoftwareProvider,
//     storage::StorageManager,
// };

// // Base Test Trait
// pub trait TestBase: ProviderTest + KeyTest {
//     fn run_all_tests(&self) {
//         self.run_provider_tests();
//         self.run_key_tests();
//     }
// }

// // Provider Test Trait
// pub trait ProviderTest: DHExchangeTest + KeyDerivationTest {
//     type ProviderImplType: ProviderImpl;

//     #[allow(unused)]
//     fn setup_provider(&self) -> Provider;
//     #[allow(unused)]
//     fn get_storage_manager(&self) -> StorageManager;

//     fn run_provider_tests(&self) {
//         self.run_dh_exchange_tests();
//         self.run_derive_key_tests();
//     }
// }

// // Key Test Trait
// pub trait KeyTest: KeyHandleTest + KeyPairHandleTest {
//     type ProviderImplType: ProviderImpl;

//     #[allow(unused)]
//     fn setup_provider(&self) -> Provider;

//     fn run_key_tests(&self) {
//         self.run_key_handle_tests();
//         self.run_key_pair_handle_tests();
//     }
// }

// // DH Exchange Test Trait
// pub trait DHExchangeTest {
//     fn test_dh_exchange_success(&self);
//     fn test_dh_exchange_derive_symmetric_key(&self);
//     fn test_dh_exchange_with_invalid_public_key(&self);
//     fn test_dh_exchange_private_key_consumed(&self);

//     fn run_dh_exchange_tests(&self) {
//         self.test_dh_exchange_success();
//         self.test_dh_exchange_derive_symmetric_key();
//         self.test_dh_exchange_with_invalid_public_key();
//         self.test_dh_exchange_private_key_consumed();
//     }
// }

// // Key Derivation Test Trait
// pub trait KeyDerivationTest {
//     fn test_successful_key_derivation(&self);
//     fn test_different_passwords_yield_different_keys(&self);
//     fn test_different_salts_yield_different_keys(&self);
//     fn test_short_salt_length_fails(&self);
//     fn test_long_salt_length_fails(&self);

//     fn run_derive_key_tests(&self) {
//         self.test_successful_key_derivation();
//         self.test_different_passwords_yield_different_keys();
//         self.test_different_salts_yield_different_keys();
//         self.test_short_salt_length_fails();
//         self.test_long_salt_length_fails();
//     }
// }

// // KeyHandle Test Trait
// pub trait KeyHandleTest {
//     fn test_encrypt_decrypt_data(&self);
//     fn test_encrypt_decrypt_empty_data(&self);
//     fn test_decrypt_with_wrong_key(&self);
//     fn test_decrypt_modified_ciphertext(&self);
//     fn test_id_method_key_handle(&self);
//     fn test_encrypt_decrypt_large_data(&self);
//     fn test_encrypt_same_plaintext_multiple_times(&self);
//     fn test_decrypt_random_data(&self);
//     fn test_decrypt_short_data(&self);
//     fn test_encrypt_decrypt_different_cipher_spec(&self);
//     fn test_encrypt_decrypt_multiple_keys(&self);

//     fn run_key_handle_tests(&self) {
//         self.test_encrypt_decrypt_data();
//         self.test_encrypt_decrypt_empty_data();
//         self.test_decrypt_with_wrong_key();
//         self.test_decrypt_modified_ciphertext();
//         self.test_id_method_key_handle();
//         self.test_encrypt_decrypt_large_data();
//         self.test_encrypt_same_plaintext_multiple_times();
//         self.test_decrypt_random_data();
//         self.test_decrypt_short_data();
//         self.test_encrypt_decrypt_different_cipher_spec();
//         self.test_encrypt_decrypt_multiple_keys();
//     }
// }

// // KeyPairHandle Test Trait
// pub trait KeyPairHandleTest {
//     fn test_sign_and_verify(&self);
//     fn test_verify_with_wrong_data(&self);
//     fn test_verify_with_wrong_key(&self);
//     fn test_get_public_key(&self);
//     fn test_sign_with_public_only_key(&self);
//     fn test_verify_with_public_only_key(&self);
//     fn test_id_method_key_pair_handle(&self);

//     fn run_key_pair_handle_tests(&self) {
//         self.test_sign_and_verify();
//         self.test_verify_with_wrong_data();
//         self.test_verify_with_wrong_key();
//         self.test_get_public_key();
//         self.test_sign_with_public_only_key();
//         self.test_verify_with_public_only_key();
//         self.test_id_method_key_pair_handle();
//     }
// }

// // Aggregated Test Trait for SoftwareProvider
// #[allow(unused)]
// pub trait SecureElementTests:
//     TestBase
//     + ProviderTest
//     + KeyTest
//     + DHExchangeTest
//     + KeyDerivationTest
//     + KeyHandleTest
//     + KeyPairHandleTest
// {
// }

// impl SecureElementTests for SoftwareProvider {}
// impl TestBase for SoftwareProvider {}
// impl KeyTest for SoftwareProvider {
//     type ProviderImplType = Self;

//     fn setup_provider(&self) -> Provider {
//         todo!()
//     }
// }

// impl ProviderTest for SoftwareProvider {
//     type ProviderImplType = Self;

//     fn setup_provider(&self) -> Provider {
//         todo!()
//     }

//     fn get_storage_manager(&self) -> StorageManager {
//         todo!()
//     }
// }

// impl DHExchangeTest for SoftwareProvider {
//     fn test_dh_exchange_success(&self) {
//         todo!()
//     }

//     fn test_dh_exchange_derive_symmetric_key(&self) {
//         todo!()
//     }

//     fn test_dh_exchange_with_invalid_public_key(&self) {
//         todo!()
//     }

//     fn test_dh_exchange_private_key_consumed(&self) {
//         todo!()
//     }
// }

// impl KeyDerivationTest for SoftwareProvider {
//     fn test_successful_key_derivation(&self) {
//         todo!()
//     }

//     fn test_different_passwords_yield_different_keys(&self) {
//         todo!()
//     }

//     fn test_different_salts_yield_different_keys(&self) {
//         todo!()
//     }

//     fn test_short_salt_length_fails(&self) {
//         todo!()
//     }

//     fn test_long_salt_length_fails(&self) {
//         todo!()
//     }
// }

// impl KeyHandleTest for SoftwareProvider {
//     fn test_encrypt_decrypt_data(&self) {
//         todo!()
//     }

//     fn test_encrypt_decrypt_empty_data(&self) {
//         todo!()
//     }

//     fn test_decrypt_with_wrong_key(&self) {
//         todo!()
//     }

//     fn test_decrypt_modified_ciphertext(&self) {
//         todo!()
//     }

//     fn test_id_method_key_handle(&self) {
//         todo!()
//     }

//     fn test_encrypt_decrypt_large_data(&self) {
//         todo!()
//     }

//     fn test_encrypt_same_plaintext_multiple_times(&self) {
//         todo!()
//     }

//     fn test_decrypt_random_data(&self) {
//         todo!()
//     }

//     fn test_decrypt_short_data(&self) {
//         todo!()
//     }

//     fn test_encrypt_decrypt_different_cipher_spec(&self) {
//         todo!()
//     }

//     fn test_encrypt_decrypt_multiple_keys(&self) {
//         todo!()
//     }
// }

// fn create_provider(impl_config: ProviderImplConfig) -> Result<SoftwareProvider, CalError> {
//     let storage_manager = StorageManager::new(
//         "SoftwareProvider".to_owned(),
//         &impl_config.additional_config,
//     )?;
//     Ok(SoftwareProvider::new(impl_config, storage_manager))
// }

// #[cfg(test)]
// mod test {
//     use std::sync::LazyLock;

//     use crate::tests::TestStore;

//     use super::*;

//     static mut STORE: LazyLock<TestStore> = LazyLock::new(TestStore::new);

//     impl KeyPairHandleTest for SoftwareProvider {
//         fn test_sign_and_verify(&self) {
//             todo!()
//         }

//         fn test_verify_with_wrong_data(&self) {
//             todo!()
//         }

//         fn test_verify_with_wrong_key(&self) {
//             todo!()
//         }

//         fn test_get_public_key(&self) {
//             todo!()
//         }

//         fn test_sign_with_public_only_key(&self) {
//             todo!()
//         }

//         fn test_verify_with_public_only_key(&self) {
//             todo!()
//         }

//         fn test_id_method_key_pair_handle(&self) {
//             todo!()
//         }
//     }

//     fn setup() -> SoftwareProvider {
//         let impl_config = unsafe { STORE.impl_config().clone() };
//         create_provider(impl_config).unwrap()
//     }

//     #[test]
//     fn software_provider_test_id_method_key_pair_handle() {
//         let software_provider = setup();
//         software_provider.test_id_method_key_pair_handle();
//     }
// }

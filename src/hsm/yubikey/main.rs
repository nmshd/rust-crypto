use crate::common::crypto::algorithms::encryption::AsymmetricEncryption;
use crate::common::crypto::KeyUsage;
use crate::common::traits::module_provider::Provider;
use crate::hsm::yubikey::YubiKeyProvider;

fn main() {
    let mut provider = YubiKeyProvider::new("test_rsa_key".to_string());
    let _ = provider.initialize_module();
    let config = crate::common::traits::module_provider_config::ProviderConfig::new(AsymmetricEncryption::Rsa, Some(KeyUsage::SignEncrypt));
    let _ = provider.create_key("test_rsa_key", config);

}
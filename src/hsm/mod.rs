use crate::common::crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage};
use crate::common::traits::module_provider_config::ProviderConfig;

pub mod core;
pub mod nitrokey;

#[cfg(feature = "yubi")]
pub mod yubikey;

#[derive(Debug)]
pub struct HsmProviderConfig {
    pub(super) key_algorithm: AsymmetricEncryption,
    pub(super) key_usage: Vec<KeyUsage>,
}

impl ProviderConfig for HsmProviderConfig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HsmProviderConfig {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        key_algorithm: AsymmetricEncryption,
        key_usage: Vec<KeyUsage>,
    ) -> Box<dyn ProviderConfig> {
        Box::new(Self {
            key_algorithm,
            key_usage,
        })
    }
}

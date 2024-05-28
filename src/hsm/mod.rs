use crate::common::crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage};
use crate::common::traits::module_provider_config::ProviderConfig;
use std::sync::Arc;

pub mod core;
pub mod nitrokey;

#[cfg(feature = "yubikey")]
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
    ) -> Arc<dyn ProviderConfig + Send + Sync> {
        Arc::new(Self {
            key_algorithm,
            key_usage,
        })
    }
}

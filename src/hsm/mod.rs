use crate::common::crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage};

pub mod core;
pub mod nitrokey;

//#[cfg(feature = "yubikey")]
pub mod yubikey;

pub struct ProviderConfig {
    pub(super) key_algorithm: AsymmetricEncryption,
    pub(super) key_usage: Option<KeyUsage>,
}

impl ProviderConfig {
    pub fn new(key_algorithm: AsymmetricEncryption, key_usage: Option<KeyUsage>) -> Self {
        Self {
            key_algorithm,
            key_usage,
        }
    }
}

use crate::common::crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage};
use yubikey::piv::SlotId;

pub mod core;
pub mod nitrokey;
pub mod yubikey;

pub struct ProviderConfig {
    pub(super) key_algorithm: AsymmetricEncryption,
    pub(super) key_usage: Option<KeyUsage>,
    pub(super) slot_id: SlotId,
}

impl ProviderConfig {
    pub fn new(key_algorithm: AsymmetricEncryption, key_usage: Option<KeyUsage>) -> Self {
        Self {
            key_algorithm,
            key_usage,
            slot_id: None,
        }
    }
}

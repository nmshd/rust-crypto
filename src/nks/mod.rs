use std::any::Any;
use crate::common::crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers};
use crate::common::crypto::algorithms::hashes::Hash;
use crate::common::crypto::KeyUsage;
use crate::common::traits::module_provider_config::ProviderConfig;

#[cfg(feature = "hcvault")]
pub mod hcvault;
#[cfg(feature = "core")]
pub mod core;


#[derive(Debug, Clone, Default)]
pub struct NksConfig {
    pub nks_token: String,
    pub nks_address: String,
    pub key_algorithm: AsymmetricEncryption,
    pub hash: Hash,
    pub key_usages: Vec<KeyUsage>,
}

impl ProviderConfig for crate::nks::NksConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl crate::nks::NksConfig {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        nks_token: String,
        nks_address: String,
        key_algorithm: AsymmetricEncryption,
        hash: Hash,
        key_usages: Vec<KeyUsage>,
    ) -> Box<dyn ProviderConfig> {
        Box::new(Self {
            nks_token,
            nks_address,
            key_algorithm,
            hash,
            key_usages,
        })
    }
}

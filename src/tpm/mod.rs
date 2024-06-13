use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers},
            hashes::Hash,
        },
        KeyUsage,
    },
    traits::module_provider_config::ProviderConfig,
};
use std::any::Any;

#[cfg(feature = "android")]
pub mod android;
pub mod core;
#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "macos")]
pub mod macos;
#[cfg(feature = "win")]
pub mod win;

#[derive(Debug, Clone, Default)]
pub struct TpmConfig {
    pub key_algorithm: AsymmetricEncryption,
    pub sym_algorithm: BlockCiphers,
    pub hash: Hash,
    pub key_usages: Vec<KeyUsage>,
}

impl ProviderConfig for TpmConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl TpmConfig {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: BlockCiphers,
        hash: Hash,
        key_usages: Vec<KeyUsage>,
    ) -> Box<dyn Any> {
        Box::new(Self {
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        })
    }
}

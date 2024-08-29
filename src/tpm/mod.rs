use async_trait::async_trait;

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
    pub key_algorithm: Option<AsymmetricEncryption>,
    pub sym_algorithm: Option<BlockCiphers>,
    pub hash: Option<Hash>,
    pub key_usages: Option<Vec<KeyUsage>>,
}

#[async_trait]
impl ProviderConfig for TpmConfig {
    async fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

impl TpmConfig {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        key_algorithm: Option<AsymmetricEncryption>,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Option<Vec<KeyUsage>>,
    ) -> Box<dyn ProviderConfig> {
        Box::new(Self {
            key_algorithm,
            sym_algorithm,
            hash,
            key_usages,
        })
    }
}

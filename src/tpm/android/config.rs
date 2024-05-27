use std::any::Any;

use robusta_jni::jni::JavaVM;

use crate::common::{
    crypto::{
        algorithms::encryption::{AsymmetricEncryption, BlockCiphers},
        algorithms::hashes::Hash,
        KeyUsage,
    },
    traits::module_provider_config::ProviderConfig,
};

pub struct AndroidConfig {
    pub key_algo: Option<AsymmetricEncryption>,
    pub sym_algo: Option<BlockCiphers>,
    pub hash: Option<Hash>,
    pub key_usages: Option<Vec<KeyUsage>>,
    pub vm: Option<JavaVM>,
}

impl std::fmt::Debug for AndroidConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidProvider")
            .field("key_algo", &self.key_algo)
            .field("sym_algo", &self.sym_algo)
            .field("hash", &self.hash)
            .field("key_usages", &self.key_usages)
            .finish()
    }
}

impl ProviderConfig for AndroidConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

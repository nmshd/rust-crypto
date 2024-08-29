use std::{any::Any, sync::Arc};

use async_std::sync::Mutex;
use async_trait::async_trait;
use robusta_jni::jni::JavaVM;

use crate::common::{
    crypto::{
        algorithms::encryption::{AsymmetricEncryption, BlockCiphers},
        algorithms::hashes::Hash,
        KeyUsage,
    },
    traits::module_provider_config::ProviderConfig,
};

#[derive(Debug, Clone, Copy)]
pub enum EncryptionMode {
    Sym(BlockCiphers),
    ASym {
        algo: AsymmetricEncryption,
        digest: Hash,
    },
}

#[derive(Clone)]
pub struct AndroidConfig {
    pub mode: EncryptionMode,
    pub key_usages: Vec<KeyUsage>,
    pub hardware_backed: bool,
    pub vm: Option<Arc<Mutex<JavaVM>>>,
}

impl std::fmt::Debug for AndroidConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidProvider")
            .field("mode", &self.mode)
            .field("key_usages", &self.key_usages)
            .field("hardware_backed", &self.hardware_backed)
            .finish()
    }
}

#[async_trait]
impl ProviderConfig for AndroidConfig {
    async fn as_any(&self) -> &dyn Any {
        self as &dyn Any
    }
}

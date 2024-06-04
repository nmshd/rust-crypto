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

#[derive(Debug, Clone, Copy)]
pub enum EncryptionMode {
    Sym(BlockCiphers),
    ASym {
        algo: AsymmetricEncryption,
        digest: Hash,
    },
}

pub struct AndroidConfig {
    pub mode: EncryptionMode,
    pub key_usages: Vec<KeyUsage>,
    pub hardware_backed: bool,
    pub vm: Option<JavaVM>,
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

impl ProviderConfig for AndroidConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

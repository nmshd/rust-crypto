use std::any::Any;

use robusta_jni::jni::JavaVM;

use crate::common::{
    crypto::{EncryptionMode, KeyUsage},
    traits::module_provider_config::ProviderConfig,
};

/// Represents the configuration for the Android provider.
pub struct AndroidConfig {
    /// The encryption mode used by the provider.
    pub mode: EncryptionMode,
    /// The allowed key usages for the provider.
    pub key_usages: Vec<KeyUsage>,
    /// Indicates whether keys should be hardware-backed. If `true`, keys are stored in secure
    /// hardware. If the hardware does not support hardware-backed keys, all operations will fail.
    pub hardware_backed: bool,
    /// A Java VM instance used to interact with the Android Keystore.
    /// While in most cases the Java VM can be retrieved programmatically, it is recommended to
    /// provide it explicitly to avoid potential issues.
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

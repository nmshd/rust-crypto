//TODO use CAL once it can compile
//use crate::common::traits::module_provider::Provider;
#[cfg(feature = "hcvault")]
use crate::nks::hcvault::NksProvider;
use std::sync::{Arc, Mutex};
use crate::common::traits::module_provider::Provider;

/// Represents the different environments where a Network Key Storage (nks) can operate.
///
/// This enum is designed to distinguish between various Network Key Storages, like HashiCorp Vault.
/// It provides a unified way to handle nks operations across different platforms.
#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum NksType {
    /// Represents the nks environment on HashiCorp Vault platforms.
    #[cfg(feature = "hcvault")]
    HCVault,
    /// Represents an unsupported or unknown nks environment.
    None,
}

/// Provides a default `NksType` based on the compile-time target operating system.
///
/// This implementation enables automatic selection of the nks type most appropriate
/// for the current target Network Key Storage, facilitating platform-agnostic nks handling.
impl Default for NksType {
    #[allow(unreachable_code)]
    fn default() -> Self {

        #[cfg(feature = "hcvault")]
        return NksType::HCVault;

        NksType::None
    }
}

/// Enables conversion from a string slice to a `NksType`.
///
/// This implementation allows for dynamic nks type determination based on string values,
/// useful for configuration or runtime environment specification.
impl From<&str> for NksType {
    fn from(s: &str) -> Self {
        match s {
            #[cfg(feature = "hcvault")]
            "HCVault" => NksType::HCVault,
            _ => panic!("Unsupported NksType"),
        }
    }
}

/// Manages instances of nks providers based on the specified `NksType`.
///
/// This structure is responsible for creating and encapsulating a nks provider instance,
/// allowing for nks operations such as key management and cryptographic functions
/// to be performed in a platform-specific manner.
#[repr(C)]
pub struct NksInstance {
    name: String,
    instance: Box<dyn Provider>,
}

/// Facilitates the creation and management of nks provider instances.
impl NksInstance {
    /// Creates a new nks provider instance based on the specified `NksType`.
    ///
    /// This method abstracts over the differences between nks implementations across
    /// various platforms, providing a unified interface for nks operations.
    ///
    /// # Arguments
    /// * `key_id` - A unique identifier for the nks key.
    /// * `nks_type` - A reference to the `NksType` indicating the environment of the nks.
    ///
    /// # Returns
    /// An `Arc<dyn Provider>` encapsulating the created nks provider instance.
    pub fn create_instance(key_id: String, tpm_type: &NksType) -> Arc<Mutex<dyn Provider>> {
        match tpm_type {
            #[cfg(feature = "hcvault")]
            NksType::HCVault => {
                let instance = NksProvider::new(key_id);
                Arc::new(Mutex::new(instance))
            }
            NksType::None => todo!(),
        }
    }
}

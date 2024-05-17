use super::traits::{log_config::LogConfig, module_provider::Provider};
#[cfg(feature = "hsm")]
use crate::hsm::core::instance::{HsmInstance, HsmType};
#[cfg(feature = "tpm")]
use crate::tpm::core::instance::{TpmInstance, TpmType};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

type ProviderArc = Arc<Mutex<dyn Provider>>;
type SecurityModuleMap = HashMap<SecurityModule, ProviderArc>;
type SecurityModuleInstances = Lazy<Mutex<SecurityModuleMap>>;

/// Represents the available types of security modules in the system.
///
/// This enum categorizes security modules into HSM (Hardware Security Module) and
/// TPM (Trusted Platform Module), allowing for a unified interface when working with different types of security modules.
#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum SecurityModule {
    #[cfg(feature = "hsm")]
    Hsm(HsmType),
    #[cfg(feature = "tpm")]
    Tpm(TpmType),
}

/// Provides conversion from a string slice to a `SecurityModule` variant.
///
/// This implementation allows for easy instantiation of `SecurityModule` variants
/// from string identifiers, facilitating user or configuration-based module selection.
impl From<&str> for SecurityModule {
    fn from(item: &str) -> Self {
        match item {
            #[cfg(feature = "tpm")]
            "TPM" => SecurityModule::Tpm(TpmType::default()),
            #[cfg(feature = "hsm")]
            "HSM" => SecurityModule::Hsm(HsmType::default()),
            _ => panic!("Unsupported Security Module type"),
        }
    }
}

/// A thread-safe, lazily-initialized global registry of security module instances.
///
/// This static variable holds a `Mutex`-protected `HashMap` that maps `SecurityModule`
/// variants to their corresponding provider instances. It ensures that module instances
/// are unique and accessible across the application.
static INSTANCES: SecurityModuleInstances = Lazy::new(|| Mutex::new(HashMap::new()));
static LOGGING_INITIALIZED: Mutex<bool> = Mutex::new(false);

/// A container struct for security module-related functionality.
///
/// This struct serves as a namespace for functions related to security module instances,
/// such as retrieving and creating them.
#[repr(C)]
pub struct SecModules {}

/// Provides methods related to managing and accessing security module instances.
impl SecModules {
    /// Retrieves or creates an instance of a security module based on the provided key and type.
    ///
    /// If an instance for the given module and key does not exist, it is created and stored.
    /// Otherwise, the existing instance is returned.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A `String` identifier for the security module instance.
    /// * `module` - The `SecurityModule` variant representing the type of module to retrieve or create.
    ///
    /// # Returns
    ///
    /// An `Option` containing an `Arc<Mutex<dyn Provider>>` to the requested module instance,
    /// or `None` if the module type is not supported or an error occurs during instance creation.
    pub fn get_instance(
        key_id: String,
        module: SecurityModule,
        log: Option<Box<dyn LogConfig>>,
    ) -> Option<Arc<Mutex<dyn Provider>>> {
        // Initialize logging once
        if !*LOGGING_INITIALIZED.lock().unwrap() {
            if let Some(log_inst) = log {
                log_inst.setup_logging();
            }
            *LOGGING_INITIALIZED.lock().unwrap() = true;
        }

        // Check if requested instance is in cache. If not, create a new instance
        let mut instances = INSTANCES.lock().unwrap();
        if !instances.contains_key(&module) {
            let instance = SecModule::create_instance(key_id, &module);
            instances.insert(module.clone(), instance?);
        }

        instances.get(&module).cloned()
    }
}

/// Represents a specific instance of a security module.
///
/// This struct is used internally to manage individual instances of security modules,
/// encapsulating the module's type and the provider instance that handles its functionality.
#[repr(C)]
struct SecModule {
    name: String,
    instance: Arc<Mutex<dyn Provider>>,
}

/// Encapsulates functionality for creating security module instances.
impl SecModule {
    /// Creates and returns an instance of a security module provider based on the module type.
    ///
    /// This function is responsible for instantiating providers for HSM and TPM modules.
    /// It delegates the instantiation to the specific module's implementation.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A `String` identifier for the security module instance.
    /// * `module` - A reference to the `SecurityModule` for which to create the instance.
    ///
    /// # Returns
    ///
    /// An `Arc<Mutex<dyn Provider>>` representing the created module instance,
    /// or `None` if the module type is not supported or an error occurs during instance creation.
    fn create_instance(
        key_id: String,
        module: &SecurityModule,
    ) -> Option<Arc<Mutex<dyn Provider>>> {
        match module {
            #[cfg(feature = "hsm")]
            SecurityModule::Hsm(hsm_type) => Some(HsmInstance::create_instance(key_id, hsm_type)),
            #[cfg(feature = "tpm")]
            SecurityModule::Tpm(tpm_type) => Some(TpmInstance::create_instance(key_id, tpm_type)),
            // _ => unimplemented!(),
        }
    }
}

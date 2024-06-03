use std::any::Any;
use std::fmt;
use std::fmt::{Debug, Formatter};

use robusta_jni::jni::{JavaVM, JNIEnv};
use tracing::instrument;

use crate::common::crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers};
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::SecurityModuleError;

mod interface;
pub mod key_handle;
pub mod provider;

/// A TPM-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations in a Samsung environment. This provider uses the Java Native Interface
/// and the Android Keystore API to access the TPM "Knox Vault" developed by Samsung. In theory,
/// this code should also work for other TPMs on Android Devices, though it is only tested with Knox Vault
#[repr(C)]
pub struct KnoxProvider {
    config: Option<KnoxConfig>,
}

///implements the Debug trait for KnoxProvider to facilitate logging
impl Debug for KnoxProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnoxProvider")
            .field("config", &self.config)
            .finish()
    }
}

///Provides functions to manage the KnoxProvider and the stored values within
impl KnoxProvider {
    /// Constructs a new `TpmProvider`.
    ///
    /// # Returns
    ///
    /// A new empty instance of `TpmProvider`.
    #[instrument]
    pub fn new() -> Self {
        Self { config: None }
    }

    /// Sets the configuration for the `Knox` instance.
    ///
    /// # Arguments
    ///
    /// * `config` - A `KnoxConfig` instance that contains the configuration settings.
    fn set_config(&mut self, config: KnoxConfig) -> () {
        self.config = Some(config);
    }

    ///Get the JavaVM stored in &self and provides the JNIEnv based on it
    /// # Returns
    ///
    /// a JNIEnv on success to be used for JNI method calls.
    /// If the KnoxConfig has not been loaded yet or contains an invalid JavaVM, an error is returned
    fn get_env(&self) -> Result<JNIEnv, SecurityModuleError> {
        if self.config.is_none() { return Err(SecurityModuleError::InitializationError(String::from("No key loaded"))) }
        let conf = self.config.as_ref().ok_or(
            SecurityModuleError::InitializationError(String::from("failed to store config data")))?;
        let env = conf.vm.get_env().unwrap();
        Ok(env)
    }

    ///Converts the config parameter to a KnoxConfig
    fn downcast_config(config: Box<dyn Any>) -> Result<KnoxConfig, SecurityModuleError> {
        let config = *config
            .downcast::<KnoxConfig>()
            .map_err(|err| SecurityModuleError::InitializationError(format!("wrong config provided: {:?}", err)))?;
        Ok(config)
    }
}

/// A struct defining the needed values for the create_key() and load_key() functions
/// At any time, either a key_algorithm OR a sym_algorithm must be supplied, not both.
/// For hashing operations, SHA-256 is always used since it is the only one available on Knox Vault
/// The last needed parameter is a JavaVM that is needed to call the Android KeystoreAPI
pub struct KnoxConfig {
    pub key_algorithm: Option<AsymmetricEncryption>,
    pub sym_algorithm: Option<BlockCiphers>,
    pub vm: JavaVM
}

/// implements the debug trait for KnoxConfig for logging
impl Debug for KnoxConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnoxConfig")
            .field("key_algorithm", &self.key_algorithm)
            .field("sym_algorithm", &self.sym_algorithm)
            .field("JavaVM", &"Contains a JavaVM to interact with Java")
            .finish()
    }
}

///implements ProviderConfig for KnoxConfig
impl ProviderConfig for KnoxConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Implements KnoxConfig and provides a constructor
impl KnoxConfig {
    /// creates a new KnoxConfig
    /// At any time, either a key_algorithm OR a sym_algorithm must be supplied, not both.
    /// Otherwise, load_key() or create_key() will return an Error.
    /// The last needed parameter is a JavaVM that is needed to call the Android KeystoreAPI
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
         key_algorithm: Option<AsymmetricEncryption>,
         sym_algorithm: Option<BlockCiphers>,
         vm: JavaVM
    ) -> KnoxConfig {
        Self {
            key_algorithm,
            sym_algorithm,
            vm,
        }
    }
}
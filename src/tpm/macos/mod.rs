use crate::{common::{crypto::algorithms::{encryption::AsymmetricEncryption, hashes::Hash}, traits::module_provider_config::ProviderConfig}, SecurityModuleError};
use anyhow::Result;
use std::fmt::{Debug, Formatter};
use std::any::Any;

pub mod key_handle;
pub mod provider;
pub mod logger;

// Provider Setup - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
#[derive(Clone, Debug)]
#[repr(C)]
pub struct SecureEnclaveProvider {
    pub(super) key_id: String, 
    config: Option<SecureEnclaveConfig>
}

impl SecureEnclaveProvider {

    /// Constructs a new `SecureEnclaveProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    ///
    /// # Returns
    ///
    /// A new instance of `SecureEnclaveProvider` with the specified `key_id`.
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            config: None
        }
    }

    pub fn set_config (&mut self, config: SecureEnclaveConfig) -> Result <(), SecurityModuleError> {
        self.config = Some(config);
        Ok(())
    }
}

// Config Setup - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

#[derive(Clone)]
pub struct SecureEnclaveConfig {
    pub asym_algorithm: Option<AsymmetricEncryption>,
    pub hash: Option<Hash>
}

impl SecureEnclaveConfig{

    /// Constructs a new `SecureEnclaveConfig`.
    /// 
    /// The sym_algorithm is not supported yet.
    /// 
    /// # Arguments
    /// 
    /// * `asym_algorithm` - The asymmetric algorithm to be used for the key.
    /// 
    /// * `hash` - The hash algorithm to be used for the key.
    /// 
    /// # Returns
    /// 
    /// A new instance of `SecureEnclaveConfig` with the specified `asym_algorithm` and `hash`.
    pub fn new(asym_algorithm: Option<AsymmetricEncryption>, hash: Option<Hash>) -> SecureEnclaveConfig {
        Self {
            asym_algorithm, 
            hash, 
        }
    }
}

impl Debug for SecureEnclaveConfig {

    /// Formats the `SecureEnclaveConfig` struct for debugging purposes.
    /// 
    /// # Arguments
    /// 
    /// * `f` - A mutable reference to a `Formatter` object.
    /// 
    /// # Returns
    /// 
    /// A `Result` containing the formatted `SecureEnclaveConfig` struct.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmProvider")
            .field("key_algorithm", &self.asym_algorithm)
            .field("asym_algorithm", &self.asym_algorithm)
            // .field("sym_algorithm", &self.sym_algorithm) // Not supported by Secure Enclave
            .field("hash", &self.hash)
            .finish()
    }
}

impl ProviderConfig for SecureEnclaveConfig {
    /// Returns the `SecureEnclaveConfig` as a reference.
    fn as_any(&self) -> &dyn Any {
        self
    }
}

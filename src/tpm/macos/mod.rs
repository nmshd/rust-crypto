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
    pub key_algorithm: Option<AsymmetricEncryption>, 
    pub asym_algorithm: Option<AsymmetricEncryption>,
    // pub sym_algorithm: Option<BlockCiphers>, // Not supported by Secure Enclave
    pub hash: Option<Hash>
}

impl SecureEnclaveConfig{
    pub fn new(key_algorithm: Option<AsymmetricEncryption>, asym_algorithm: Option<AsymmetricEncryption>, hash: Option<Hash>) -> SecureEnclaveConfig {
        Self {
            key_algorithm, 
            asym_algorithm, 
            // sym_algorithm: None, // Not supported by Secure Enclave
            hash, 
        }
    }
}

impl Debug for SecureEnclaveConfig {
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
    fn as_any(&self) -> &dyn Any {
        self
    }
}

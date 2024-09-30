use super::key_handle::{DHKeyExchange, KeyHandle, KeyPairHandle};
use crate::common::{
    config::{AlgorithmMetadata, DHSpec, KeyPairSpec, KeySpec, ProviderConfig},
    error::SecurityModuleError,
};
use async_trait::async_trait;

#[async_trait]
pub trait ProviderFactory {
    fn get_name(&self) -> String;
    async fn get_capabilities(&mut self) -> AlgorithmMetadata;
    async fn check_config(&mut self, config: ProviderConfig) -> bool;
    async fn create_provider(self, config: ProviderConfig) -> Box<dyn Provider>;
}

/// Defines the interface for a security module provider.
///
/// This trait encapsulates operations related to cryptographic key creation and storage. It ensures a unified approach to interacting with different types
/// of security modules.
#[async_trait]
pub trait Provider {
    /// Creates a new symmetric key identified by `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `spec` - The key specification.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `KeyHandle`, allowing further operations with this key.
    /// On failure, it returns a `SecurityModuleError`.
    async fn create_key(
        &mut self,
        spec: KeySpec,
    ) -> Result<Box<dyn KeyHandle>, SecurityModuleError>;

    /// Loads an existing symmetric key identified by `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `spec` - The key specification.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `KeyHandle`, allowing further operations with this key.
    /// On failure, it returns a `SecurityModuleError`.
    async fn load_key(&mut self, key_id: String)
        -> Result<Box<dyn KeyHandle>, SecurityModuleError>;

    /// Creates a new asymmetric key pair identified by `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the keypair to be created.
    /// * `spec` - The key specification.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `KeyPairHandle`, allowing further operations with this key pair.
    /// On failure, it returns a `SecurityModuleError`.
    async fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<Box<dyn KeyPairHandle>, SecurityModuleError>;

    /// Loads an existing asymmetric keypair identified by `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the keypair to be loaded.
    /// * `spec` - The key specification.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `KeyPairHandle`, allowing further operations with this key pair.
    /// On failure, it returns a `SecurityModuleError`.
    async fn load_key_pair(
        &mut self,
        key_id: String,
    ) -> Result<Box<dyn KeyPairHandle>, SecurityModuleError>;

    /// Generates a key pair suited for a Diffie-Hellman Key Exchange
    ///
    /// # Arguments
    ///
    /// * `spec` - A specification for the exchange process and resulting symmetric key
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `DHKeyExchange`, allowing further operations with this key pair.
    /// On failure, it returns a `SecurityModuleError`.
    async fn start_dh_exchange(
        &mut self,
        spec: DHSpec,
    ) -> Result<Box<dyn DHKeyExchange>, SecurityModuleError>;
}

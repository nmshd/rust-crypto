use async_trait::async_trait;
use derive_more::derive::From;
use enum_dispatch::enum_dispatch;
use flutter_rust_bridge::frb;

use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig},
        error::SecurityModuleError,
        DHExchange, KeyHandle, KeyPairHandle,
    },
    stub::{StubProvider, StubProviderFactory},
    tpm::android::provider::{AndroidProvider, AndroidProviderFactory},
};

#[enum_dispatch(ProviderFactoryEnum)]
pub(crate) trait ProviderFactory: Send + Sync {
    fn get_name(&self) -> String;

    /// Returns security level and supported algorithms of a provider.
    ///
    /// [ProviderConfig] returned stores in HashSets all Hashes, Ciphers and AsymmetricKeySpecs a provider supports.
    fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig;
    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum;
}

#[enum_dispatch]
pub(crate) enum ProviderFactoryEnum {
    StubProviderFactory,
    AndroidProviderFactory,
}

/// Defines the interface for a security module provider.
///
/// This trait encapsulates operations related to cryptographic key creation and storage. It ensures a unified approach to interacting with different types
/// of security modules.

#[enum_dispatch(ProviderImplEnum)]
pub(crate) trait ProviderImpl {
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
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError>;

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
    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, SecurityModuleError>;

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
    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, SecurityModuleError>;

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
    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, SecurityModuleError>;

    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, SecurityModuleError>;

    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError>;

    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError>;

    /// Generates a key pair suited for a Diffie-Hellman Key Exchange
    ///
    /// # Arguments
    ///
    /// * `spec` - A specification for the exchange process and resulting symmetric key
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `DHExchange`, allowing further operations with this key pair.
    /// On failure, it returns a `SecurityModuleError`.
    fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<DHExchange, SecurityModuleError>;

    fn provider_name(&self) -> String;
}

#[enum_dispatch]
pub(crate) enum ProviderImplEnum {
    StubProvider,
    AndroidProvider,
}

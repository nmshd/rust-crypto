use enum_dispatch::enum_dispatch;

use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig},
        error::CalError,
        DHExchange, KeyHandle, KeyPairHandle,
    },
    stub::{StubProvider, StubProviderFactory},
};

#[cfg(feature = "android")]
use crate::tpm::android::provider::{AndroidProvider, AndroidProviderFactory};

#[cfg(feature = "apple-secure-enclave")]
use crate::tpm::apple_secure_enclave::provider::{
    AppleSecureEnclaveFactory, AppleSecureEnclaveProvider,
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
    #[cfg(feature = "android")]
    AndroidProviderFactory,
    #[cfg(feature = "apple-secure-enclave")]
    AppleSecureEnclaveFactory,
}

/// Defines the interface for a security module provider.
///
/// This trait encapsulates operations related to cryptographic key creation and storage. It ensures a unified approach to interacting with different types
/// of security modules.

#[enum_dispatch(ProviderImplEnum)]
pub(crate) trait ProviderImpl: Send + Sync {
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
    /// On failure, it returns a `CalError`.
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError>;

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
    /// On failure, it returns a `CalError`.
    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError>;

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
    /// On failure, it returns a `CalError`.
    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError>;

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
    /// On failure, it returns a `CalError`.
    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError>;

    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError>;

    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError>;

    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError>;

    /// Generates a key pair suited for a Diffie-Hellman Key Exchange
    ///
    /// # Arguments
    ///
    /// * `spec` - A specification for the exchange process and resulting symmetric key
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains a `DHExchange`, allowing further operations with this key pair.
    /// On failure, it returns a `CalError`.
    fn start_ephemeral_dh_exchange(&mut self, spec: KeyPairSpec) -> Result<DHExchange, CalError>;

    fn provider_name(&self) -> String;

    fn get_capabilities(&self) -> ProviderConfig;
}

#[enum_dispatch]
pub(crate) enum ProviderImplEnum {
    StubProvider,
    #[cfg(feature = "android")]
    AndroidProvider,
    #[cfg(feature = "apple-secure-enclave")]
    AppleSecureEnclaveProvider,
}

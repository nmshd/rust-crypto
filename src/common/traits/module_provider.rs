#[cfg(feature = "android")]
use crate::provider::android::provider::{AndroidProvider, AndroidProviderFactory};
#[cfg(feature = "apple-secure-enclave")]
use crate::provider::apple_secure_enclave::provider::{
    AppleSecureEnclaveFactory, AppleSecureEnclaveProvider,
};
#[cfg(feature = "software")]
use crate::provider::software::{SoftwareProvider, SoftwareProviderFactory};
#[cfg(feature = "win")]
use crate::provider::win::{WindowsProvider, WindowsProviderFactory};

use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, Spec},
        crypto::algorithms::key_derivation::KDF,
        error::CalError,
        DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::CryptoHash,
};
use enum_dispatch::enum_dispatch;

#[enum_dispatch(ProviderFactoryEnum)]
pub(crate) trait ProviderFactory: Send + Sync {
    fn get_name(&self) -> Option<String>;

    /// Returns security level and supported algorithms of a provider.
    ///
    /// [`ProviderConfig`] returned stores in `HashSets` all `Hashes`, `Ciphers` and `AsymmetricKeySpecs` a provider supports.
    fn get_capabilities(&self, impl_config: ProviderImplConfig) -> Option<ProviderConfig>;
    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError>;
}

#[enum_dispatch]
pub(crate) enum ProviderFactoryEnum {
    #[cfg(feature = "android")]
    AndroidProviderFactory,
    #[cfg(feature = "apple-secure-enclave")]
    AppleSecureEnclaveFactory,
    #[cfg(feature = "software")]
    SoftwareProviderFactory,
    #[cfg(feature = "win")]
    WindowsProviderFactory,
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

    /// [DEPRECATED]: Starts a dh exchange from a raw private key and it's public key.
    ///
    /// `start_dh_exchange` of `KeyPairHandle` is preferable for use with crypto layer.
    #[allow(dead_code, unused_variables)]
    fn dh_exchange_from_keys(
        &mut self,
        public_key: &[u8],
        private_key: &[u8],
        spec: KeyPairSpec,
    ) -> Result<DHExchange, CalError> {
        unimplemented!()
    }

    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError>;

    fn provider_name(&self) -> String;

    fn get_capabilities(&self) -> Option<ProviderConfig>;

    /// Derives a high-entropy key from a low-entropy password and a unique salt
    #[allow(dead_code, unused_variables)]
    fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        algorithm: KeySpec,
        kdf: KDF,
    ) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    /// Derives a high-entropy key from a low-entropy password and a unique salt
    #[allow(dead_code, unused_variables)]
    fn derive_key_from_base(
        &self,
        base_key: &[u8],
        key_id: u64,
        context: &str,
        spec: KeySpec,
    ) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    /// Hashes the input
    #[allow(dead_code, unused_variables)]
    fn hash(&self, input: &[u8], hash: CryptoHash) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    /// Generates random bytes
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to generate
    ///
    /// # Returns
    ///
    /// A `Vec` that, on success, contains a the requested amount of random bytes.
    #[allow(dead_code, unused_variables)]
    fn get_random(&self, len: usize) -> Vec<u8> {
        unimplemented!("Random number generation is not implemented for this provider.")
    }
}

#[enum_dispatch]
pub(crate) enum ProviderImplEnum {
    #[cfg(feature = "android")]
    AndroidProvider,
    #[cfg(feature = "apple-secure-enclave")]
    AppleSecureEnclaveProvider,
    #[cfg(feature = "software")]
    SoftwareProvider,
    #[cfg(feature = "win")]
    WindowsProvider,
}

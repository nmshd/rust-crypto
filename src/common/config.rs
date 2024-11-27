#![allow(dead_code)]
use std::any::Any;
use std::fmt::Debug;
use std::{
    cmp::{Eq, Ord, PartialEq, PartialOrd},
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use strum::{EnumIter, EnumString};

use super::crypto::algorithms::{
    encryption::{AsymmetricKeySpec, Cipher},
    hashes::CryptoHash,
};

/// A type alias for a pinned, heap-allocated, dynamically dispatched future that is `Send`.
///
/// This simplifies the notation for futures returned by asynchronous functions.
pub type DynFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A thread-safe, shareable function that asynchronously retrieves data associated with a key.
///
/// The function takes a `String` key and returns a `DynFuture` resolving to an `Option<Vec<u8>>`.
/// - If the key exists, it resolves to `Some(Vec<u8>)` containing the data.
/// - If the key does not exist, it resolves to `None`.
pub type GetFn = Arc<dyn Fn(String) -> DynFuture<Option<Vec<u8>>> + Send + Sync>;

/// A thread-safe, shareable function that asynchronously stores data associated with a key.
///
/// The function takes a `String` key and a `Vec<u8>` value, and returns a `DynFuture` resolving to a `bool`.
/// - It resolves to `true` if the data was successfully stored.
/// - It resolves to `false` if the storage operation failed.
pub type StoreFn = Arc<dyn Fn(String, Vec<u8>) -> DynFuture<bool> + Send + Sync>;

/// A thread-safe, shareable function that asynchronously deletes data associated with a key.
///
/// The function takes a `String` key and returns a `DynFuture` resolving to `()`.
/// This function performs an asynchronous deletion operation and does not return any value.
pub type DeleteFn = Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A thread-safe, shareable function that asynchronously retrieves all available keys.
///
/// The function returns a `DynFuture` resolving to a `Vec<String>` containing all the keys.
pub type AllKeysFn = Arc<dyn Fn() -> DynFuture<Vec<String>> + Send + Sync>;

/// Enum describing the security level of a provider.
///
/// * [SecurityLevel::Hardware]: Provider is hardware backed (tpm, other security chips, StrongBox KeyStore).
/// * [SecurityLevel::Software]: Provder uses the systems software keystore.
/// * [SecurityLevel::Network]: Provider uses a network key store (Hashicorp).
/// * [SecurityLevel::Unsafe]: Provder uses software fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, EnumString, EnumIter)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum SecurityLevel {
    /// Highest security level
    Hardware = 4,
    Software = 3,
    Network = 2,
    Unsafe = 1,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeySpec {
    pub cipher: Cipher,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeyPairSpec {
    pub asym_spec: AsymmetricKeySpec,
    pub cipher: Option<Cipher>,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub(crate) enum SerializableSpec {
    KeySpec(KeySpec),
    KeyPairSpec(KeyPairSpec),
}

/// A trait for encapsulating additional configuration data with support for dynamic downcasting.
///
/// Implementing this trait allows different configuration types to be stored as trait objects
/// (`dyn AdditionalConfig`) and later downcasted to their concrete types when specific functionality
/// is required.
pub trait AdditionalData: Any + Debug + Send + Sync {
    /// Provides a reference to `self` as `&dyn Any` to enable downcasting to concrete types.
    fn as_any(&self) -> &dyn Any;
}

/// Automatically implements `AdditionalConfig` for any type that satisfies `Any + Debug + Send + Sync`.
///
/// This blanket implementation allows diverse types to be used as additional configuration
/// without requiring individual trait implementations. It enables dynamic configuration
/// handling by leveraging Rust's trait bounds and dynamic downcasting capabilities.
impl<T: Any + Debug + Send + Sync> AdditionalData for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A handle encapsulating additional configuration, enabling dynamic downcasting.
///
/// This struct wraps an `Arc<dyn AdditionalConfig>`, allowing for thread-safe sharing and
/// dynamic dispatch of configuration data. The `opaque` attribute ensures that this type
/// is treated as an opaque type in Flutter Rust Bridge, hiding its internal structure.
/// flutter_rust_bridge:opaque
#[derive(Debug)]
pub struct ConfigHandle {
    pub(crate) implementation: Arc<dyn AdditionalData>,
}

impl ConfigHandle {
    pub fn new(implementation: Arc<dyn AdditionalData>) -> Self {
        Self { implementation }
    }
}

impl Clone for ConfigHandle {
    fn clone(&self) -> Self {
        ConfigHandle {
            implementation: Arc::clone(&self.implementation),
        }
    }
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Debug)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct ProviderConfig {
    pub max_security_level: SecurityLevel,
    pub min_security_level: SecurityLevel,
    pub supported_ciphers: HashSet<Cipher>,
    pub supported_hashes: HashSet<CryptoHash>,
    pub supported_asym_spec: HashSet<AsymmetricKeySpec>,
}

/// flutter_rust_bridge:opaque
#[derive(Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct ProviderImplConfig {
    pub(crate) get_fn: GetFn,
    pub(crate) store_fn: StoreFn,
    pub(crate) delete_fn: DeleteFn,
    pub(crate) all_keys_fn: AllKeysFn,
    pub(crate) additional_config: Option<ConfigHandle>,
}

impl std::fmt::Debug for ProviderImplConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderImplConfig{opaque}").finish()
    }
}

impl ProviderImplConfig {
    /// Creates a new `ProviderImplConfig` instance.
    pub fn new(
        get_fn: GetFn,
        store_fn: StoreFn,
        delete_fn: DeleteFn,
        all_keys_fn: AllKeysFn,
        additional_config: Option<ConfigHandle>,
    ) -> Self {
        Self {
            get_fn,
            store_fn,
            delete_fn,
            all_keys_fn,
            additional_config,
        }
    }

    /// Creates a new stubbed `ProviderImplConfig` instance for testing or default purposes.
    pub fn new_stub(
        get_fn: GetFn,
        store_fn: StoreFn,
        delete_fn: DeleteFn,
        all_keys_fn: AllKeysFn,
    ) -> Self {
        Self::new(get_fn, store_fn, delete_fn, all_keys_fn, None)
    }

    /// Method to retrieve the additional configuration as a concrete type.
    ///
    /// This method attempts to downcast the `additional_config` to the specified concrete type `T`.
    /// If the downcast succeeds, it returns `Some(&T)`; otherwise, it returns `None`.
    pub fn get_additional_config_as<T: Any + 'static>(&self) -> Option<&T> {
        self.additional_config.as_ref().and_then(|config_handle| {
            config_handle
                .implementation
                .as_ref()
                .as_any()
                .downcast_ref::<T>()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_order() {
        assert!(SecurityLevel::Unsafe < SecurityLevel::Software);
        assert!(SecurityLevel::Software < SecurityLevel::Hardware);
    }
}

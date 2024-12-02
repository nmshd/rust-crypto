#![allow(dead_code)]
use std::fmt::Debug;
use std::{
    cmp::{Eq, Ord, PartialEq, PartialOrd},
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use super::crypto::algorithms::{
    encryption::{AsymmetricKeySpec, Cipher},
    hashes::CryptoHash,
};
use super::KeyHandle;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Highest security level
    Hardware = 4,
    Software = 3,
    Network = 2,
    Unsafe = 1,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct KeySpec {
    pub cipher: Cipher,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct KeyPairSpec {
    pub asym_spec: AsymmetricKeySpec,
    pub cipher: Option<Cipher>,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub max_security_level: SecurityLevel,
    pub min_security_level: SecurityLevel,
    pub supported_ciphers: HashSet<Cipher>,
    pub supported_hashes: HashSet<CryptoHash>,
    pub supported_asym_spec: HashSet<AsymmetricKeySpec>,
}

/// flutter_rust_bridge:opaque
#[derive(Clone)]
pub struct ProviderImplConfig {
    pub additional_config: Vec<AdditionalConfig>,
}

#[derive(Clone)]
pub enum AdditionalConfig {
    KVStoreConfig {
        get_fn: GetFn,
        store_fn: StoreFn,
        delete_fn: DeleteFn,
        all_keys_fn: AllKeysFn,
    },
    FileStoreConfig {
        db_path: String,
        secure_path: String,
        pass: String,
    },
    StorageConfig {
        key_handle: KeyHandle,
    },
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
        mut additional_config: Vec<AdditionalConfig>,
    ) -> Self {
        let kv_config = AdditionalConfig::KVStoreConfig {
            get_fn,
            store_fn,
            delete_fn,
            all_keys_fn,
        };
        additional_config.push(kv_config);
        Self { additional_config }
    }

    /// Creates a new stubbed `ProviderImplConfig` instance for testing or default purposes.
    pub fn new_stub(
        get_fn: GetFn,
        store_fn: StoreFn,
        delete_fn: DeleteFn,
        all_keys_fn: AllKeysFn,
    ) -> Self {
        Self::new(get_fn, store_fn, delete_fn, all_keys_fn, vec![])
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

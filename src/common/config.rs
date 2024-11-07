#[cfg(feature = "android")]
use std::sync::Mutex;
use std::{
    cmp::{Eq, Ord, PartialEq, PartialOrd},
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
};

#[cfg(feature = "android")]
use robusta_jni::jni::JavaVM;

use super::crypto::algorithms::{
    encryption::{AsymmetricKeySpec, Cipher},
    hashes::CryptoHash,
};

/// A type alias for a pinned, heap-allocated, dynamically dispatched future that is `Send`.
///
/// This simplifies the notation for futures returned by asynchronous functions.
type DynFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A thread-safe, shareable function that asynchronously retrieves data associated with a key.
///
/// The function takes a `String` key and returns a `DynFuture` resolving to an `Option<Vec<u8>>`.
/// - If the key exists, it resolves to `Some(Vec<u8>)` containing the data.
/// - If the key does not exist, it resolves to `None`.
type GetFn = Arc<dyn Fn(String) -> DynFuture<Option<Vec<u8>>> + Send + Sync>;

/// A thread-safe, shareable function that asynchronously stores data associated with a key.
///
/// The function takes a `String` key and a `Vec<u8>` value, and returns a `DynFuture` resolving to a `bool`.
/// - It resolves to `true` if the data was successfully stored.
/// - It resolves to `false` if the storage operation failed.
type StoreFn = Arc<dyn Fn(String, Vec<u8>) -> DynFuture<bool> + Send + Sync>;

/// A thread-safe, shareable function that asynchronously retrieves all available keys.
///
/// The function returns a `DynFuture` resolving to a `Vec<String>` containing all the keys.
type AllKeysFn = Arc<dyn Fn() -> DynFuture<Vec<String>> + Send + Sync>;

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
#[derive(Clone, Copy, Debug, Default)]
pub struct KeySpec {
    pub cipher: Cipher,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Default)]
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
    #[cfg(feature = "android")]
    pub(crate) java_vm: Option<Arc<Mutex<JavaVM>>>,
    pub(crate) get_fn: GetFn,
    pub(crate) store_fn: StoreFn,
    pub(crate) all_keys_fn: AllKeysFn,
}

impl ProviderImplConfig {
    #[cfg(feature = "android")]
    pub fn new(
        java_vm: Arc<Mutex<JavaVM>>,
        get_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>
            + 'static
            + Send
            + Sync,
        store_fn: impl Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = bool> + Send>>
            + 'static
            + Send
            + Sync,
        all_keys_fn: impl Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>
            + 'static
            + Send
            + Sync,
    ) -> Self {
        Self {
            java_vm: Some(java_vm),
            get_fn: Arc::new(get_fn),
            store_fn: Arc::new(store_fn),
            all_keys_fn: Arc::new(all_keys_fn),
        }
    }

    #[cfg(feature = "software")]
    pub fn new(
        get_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>
            + 'static
            + Send
            + Sync,
        store_fn: impl Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = bool> + Send>>
            + 'static
            + Send
            + Sync,
        all_keys_fn: impl Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>
            + 'static
            + Send
            + Sync,
    ) -> Self {
        Self {
            get_fn: Arc::new(get_fn),
            store_fn: Arc::new(store_fn),
            all_keys_fn: Arc::new(all_keys_fn),
        }
    }

    pub fn new_stub(
        get_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>
            + 'static
            + Send
            + Sync,
        store_fn: impl Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = bool> + Send>>
            + 'static
            + Send
            + Sync,
        all_keys_fn: impl Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>
            + 'static
            + Send
            + Sync,
    ) -> Self {
        Self {
            #[cfg(feature = "android")]
            java_vm: None,
            get_fn: Arc::new(get_fn),
            store_fn: Arc::new(store_fn),
            all_keys_fn: Arc::new(all_keys_fn),
        }
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

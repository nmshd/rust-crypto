use std::cmp::{Eq, Ord, PartialEq, PartialOrd};
use std::collections::HashSet;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "android")]
use std::sync::Mutex;

#[cfg(feature = "android")]
use robusta_jni::jni::JavaVM;

use super::crypto::algorithms::{
    encryption::{AsymmetricKeySpec, Cipher},
    hashes::CryptoHash,
};

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
#[derive(Clone, Copy, Debug)]
pub struct KeySpec {
    pub cipher: Cipher,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug)]
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
    pub(crate) get_fn:
        Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> + Send + Sync>,
    pub(crate) store_fn:
        Arc<dyn Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>,
    pub(crate) all_keys_fn:
        Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>> + Send + Sync>,
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

#![allow(dead_code)]
use std::any::Any;
use std::cmp::{Eq, Ord, PartialEq, PartialOrd};
use std::collections::HashSet;
use std::fmt;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use strum::EnumString;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, EnumString)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum SecurityLevel {
    /// Highest security level
    Hardware = 4,
    Software = 3,
    Network = 2,
    Unsafe = 1,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeySpec {
    pub cipher: Cipher,
    pub signing_hash: CryptoHash,
}

/// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeyPairSpec {
    pub asym_spec: AsymmetricKeySpec,
    pub cipher: Option<Cipher>,
    pub signing_hash: CryptoHash,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub(crate) enum SerializableSpec {
    KeySpec(KeySpec),
    KeyPairSpec(KeyPairSpec),
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
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) java_vm: Option<Arc<dyn Any + Send + Sync>>,
    #[cfg_attr(feature = "ts-interface", ts(type = "(id: string) => Uint8Array"))]
    pub(crate) get_fn:
        Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>> + Send + Sync>,
    #[cfg_attr(
        feature = "ts-interface",
        ts(type = "(id: string, data: Uint8Array) => boolean")
    )]
    pub(crate) store_fn:
        Arc<dyn Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>,
    #[cfg_attr(feature = "ts-interface", ts(type = "(id: string) => void"))]
    pub(crate) delete_fn:
        Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
    #[cfg_attr(feature = "ts-interface", ts(type = "() => string[]"))]
    pub(crate) all_keys_fn:
        Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>> + Send + Sync>,
}

impl ProviderImplConfig {
    pub fn new(
        java_vm: Option<Arc<dyn Any + Send + Sync>>,
        get_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>
            + 'static
            + Send
            + Sync,
        store_fn: impl Fn(String, Vec<u8>) -> Pin<Box<dyn Future<Output = bool> + Send>>
            + 'static
            + Send
            + Sync,
        delete_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + 'static + Send + Sync,
        all_keys_fn: impl Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>
            + 'static
            + Send
            + Sync,
    ) -> Self {
        Self {
            java_vm,
            get_fn: Arc::new(get_fn),
            store_fn: Arc::new(store_fn),
            delete_fn: Arc::new(delete_fn),
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
        delete_fn: impl Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + 'static + Send + Sync,
        all_keys_fn: impl Fn() -> Pin<Box<dyn Future<Output = Vec<String>> + Send>>
            + 'static
            + Send
            + Sync,
    ) -> Self {
        Self {
            java_vm: None,
            get_fn: Arc::new(get_fn),
            store_fn: Arc::new(store_fn),
            delete_fn: Arc::new(delete_fn),
            all_keys_fn: Arc::new(all_keys_fn),
        }
    }
}

impl fmt::Debug for ProviderImplConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderImplConfig")
            .field("java_vm", &self.java_vm)
            .finish()
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

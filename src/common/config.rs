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

use strum::{EnumDiscriminants, EnumIter, EnumString, IntoStaticStr};

use super::crypto::algorithms::{
    encryption::{AsymmetricKeySpec, Cipher},
    hashes::CryptoHash,
};
use super::{KeyHandle, KeyPairHandle};

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
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, EnumString, EnumIter, IntoStaticStr,
)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum SecurityLevel {
    /// Highest security level.
    ///
    /// Implies running on a TPM, HSM or TEE.
    /// The extraction of private keys is impossible.
    Hardware = 4,
    /// Keys are stored in an encrypted database or on a native software key store.
    ///
    /// Extraction of private keys is possible.
    Software = 3,
    /// NKS
    ///
    /// Extraction of private keys is possible.
    Network = 2,
    /// Lowest security level.
    ///
    /// Keys are stored in an unencrypted, insecure database or file.
    Unsafe = 1,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
/// flutter_rust_bridge:non_opaque
pub enum Spec {
    KeySpec(KeySpec),
    KeyPairSpec(KeyPairSpec),
}

/// Struct used to configure keys.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
/// flutter_rust_bridge:non_opaque
pub struct KeySpec {
    /// Cipher used for symmetric encryption.
    pub cipher: Cipher,
    /// Hash function used with HMAC.
    pub signing_hash: CryptoHash,
    /// If set to `true`, the key is going to be deleted when the handle is dropped.
    pub ephemeral: bool,
}

/// Struct used to configure key pairs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
/// flutter_rust_bridge:non_opaque
pub struct KeyPairSpec {
    /// Asymmetric algorithm to be used.
    pub asym_spec: AsymmetricKeySpec,
    /// Cipher used for hybrid encryption. If set to None, no hybrid encryption will be used.
    pub cipher: Option<Cipher>,
    /// Hash function used for signing and encrypting.
    pub signing_hash: CryptoHash,
    /// If set to true, the key pair will be discarded after the handle is dropped.
    pub ephemeral: bool,
    /// If set to true, the key can't be exported (also software keys)
    pub non_exportable: bool,
}

/// Capabilities of a Provider
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

/// Configuration needed for using or initializing providers.
///
/// Either
/// * [AdditionalConfig::KVStoreConfig]
/// * [AdditionalConfig::FileStoreConfig]
///
/// and either
/// * [AdditionalConfig::StorageConfigHMAC]
/// * [AdditionalConfig::StorageConfigDSA]
/// * [AdditionalConfig::StorageConfigPass]
///
/// need to be supplied.
///
/// ## Example
///
/// ```rust
/// use crypto_layer::prelude::*;
/// let implementation_config = ProviderImplConfig {
///       additional_config: vec![
///          AdditionalConfig::FileStoreConfig {
///              db_dir: "./testdb".to_owned(),
///          },
///          AdditionalConfig::StorageConfigPass("password".to_owned()),
///      ],
/// };
/// ```
/// flutter_rust_bridge:non_opaque
#[derive(Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct ProviderImplConfig {
    pub additional_config: Vec<AdditionalConfig>,
}

/// Configuration needed for using or initializing providers.
/// flutter_rust_bridge:non_opaque
#[derive(Clone, EnumDiscriminants)]
#[strum_discriminants(derive(EnumString, IntoStaticStr))]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum AdditionalConfig {
    #[cfg_attr(
        feature = "ts-interface",
        ts(type = "{
            get_fn: (id: string) => Uint8Array | undefined;
            store_fn: (id: string, data: Uint8Array) => boolean;
            delete_fn: (id: string) => void;
            all_keys_fn: () => string[];
        }")
    )]
    /// Callback functions acting like a hashmap for storing key metadata.
    ///
    /// Not supported by the NodeJS plugin.
    KVStoreConfig {
        get_fn: GetFn,
        store_fn: StoreFn,
        delete_fn: DeleteFn,
        all_keys_fn: AllKeysFn,
    },
    /// Configuration for the usage of the metadata file database.
    FileStoreConfig {
        /// Path to a directory where the database holding key metadata will be saved.
        db_dir: String,
    },
    /// Used for verifying the integrity of the key metadata.
    StorageConfigHMAC(KeyHandle),
    /// Used for verifying the integrity of the key metadata.
    StorageConfigDSA(KeyPairHandle),
    /// Used for verifying the integrity of the key metadata.
    StorageConfigPass(String),
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

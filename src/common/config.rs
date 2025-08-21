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
use zeroize::Zeroize;

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
/// * [SecurityLevel::Software]: Provider uses the systems software keystore.
/// * [SecurityLevel::Network]: Provider uses a network key store (HashiCorp).
/// * [SecurityLevel::Unsafe]: Provider uses software fallback.
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
// flutter_rust_bridge:non_opaque
pub enum Spec {
    KeySpec(KeySpec),
    KeyPairSpec(KeyPairSpec),
}

/// Struct used to configure keys.
///
/// It is important to note, that the configuration of a key can only happen at the point of its creation.
/// A key cannot be reconfigured.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, Zeroize, PartialEq)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
// flutter_rust_bridge:non_opaque
pub struct KeySpec {
    /// Cipher used for symmetric encryption.
    pub cipher: Cipher,

    /// Hash function used with HMAC.
    pub signing_hash: CryptoHash,

    /// If set to `true`, metadata of the key is not stored and the key is going to be deleted when the handle is dropped.
    pub ephemeral: bool,

    /// If set to `true`, the key cannot be exported.
    ///
    /// Some providers do not allow exporting keys at all, even if set to `false`.
    pub non_exportable: bool,
}

/// Struct used to configure key pairs.
///
/// It is important to note, that the configuration of a key can only happen at the point of its creation.
/// A key cannot be reconfigured.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
// flutter_rust_bridge:non_opaque
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
///
/// This configuration struct has multiple uses:
/// * Act as capabilities of a provider.
/// * Act as requirement for [`create_provider`](crate::prelude::create_provider).
///
/// Depending on the use some properties have different meanings:
/// * Currently a provider may only have one security level.
/// * The requester may ask for a provider that has at a minimum one security level or at a maximum another security level.
/// * A provider has certain algorithm he at least in some form supports.
/// * A requester may ask for minimum requirements regarding these algorithms.
///
/// ### Example
///
/// A provider might return capabilities like:
/// ```
/// # use crypto_layer::prelude::*;
/// # use std::collections::HashSet;
///
/// let apple_provider_capabilities = ProviderConfig {
///     max_security_level: SecurityLevel::Hardware,
///     min_security_level: SecurityLevel::Hardware,
///     supported_ciphers: HashSet::from([Cipher::AesGcm128, Cipher::AesGcm256]),
///     supported_asym_spec: HashSet::from([AsymmetricKeySpec::P256]),
///     supported_hashes: HashSet::from([
///         CryptoHash::Sha2_224,
///         CryptoHash::Sha2_256,
///         CryptoHash::Sha2_384,
///         CryptoHash::Sha2_512,
///     ]),
/// };
///
/// ```
/// Such provider then is ought to use a secure element (apart from the `ANDROID_PROVIDER`)
/// and at least support these algorithms **in one form or another** .
///
/// Please be aware, that `supported_ciphers` does not imply support for symmetric cryptography!
///
/// A requestor might ask for a provider with capabilities like:
/// ```
/// # use crypto_layer::prelude::*;
/// # use std::collections::HashSet;
///
/// let requested_capabilities = ProviderConfig {
///     max_security_level: SecurityLevel::Hardware,
///     min_security_level: SecurityLevel::Software,
///     supported_ciphers: HashSet::from([Cipher::AesGcm256]),
///     supported_asym_spec: HashSet::from([AsymmetricKeySpec::P256]),
///     supported_hashes: HashSet::from([
///         CryptoHash::Sha2_256,
///         CryptoHash::Sha2_512,
///     ]),
/// };
/// ```
///
/// As the requested capabilities are a subset of the provided capabilities above,
/// this requestor might be assigned the apple secure enclave provider on apple platforms.
///
// flutter_rust_bridge:non_opaque
#[derive(Clone, Debug)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct ProviderConfig {
    /// Highest security supported or maximum security requested.
    ///
    /// As an example, the software fallback provider has a maximum security level of [`SecurityLevel::Software`].
    pub max_security_level: SecurityLevel,

    /// Minimum security level supported or security level required.
    ///
    /// As an example:
    /// If one wishes to use provider that is based on a secure element, one would require [`SecurityLevel::Hardware`].
    pub min_security_level: SecurityLevel,

    /// Cipher algorithms supported in one fashion or another or cipher algorithms required.
    ///
    /// A provider might support cipher algorithms returned as capabilities in following ways:
    /// * Supports symmetric encryption with said cipher.
    /// * Supports asymmetric hybrid encryption with said cipher. (What standard is used for the hybrid encryption is not set.)
    pub supported_ciphers: HashSet<Cipher>,

    /// Hashing algorithm supported for either the use with signing (symmetric or asymmetric) operations or encryption operations (symmetric or asymmetric),
    /// or hashing algorithm required for the same purpose.
    ///
    /// A provider that supports a hash algorithm **may or may not** support following operations in combination with said hashing algorithm:
    /// * [`KeyHandle::hmac()`](crate::prelude::KeyHandle::hmac)
    /// * [`KeyHandle::verify_hmac()`](crate::prelude::KeyHandle::verify_hmac)
    /// * [`KeyHandle::encrypt()`](crate::prelude::KeyHandle::encrypt())
    /// * [`KeyHandle::decrypt_data()`](crate::prelude::KeyHandle::decrypt_data())
    /// * [`KeyPairHandle::sign_data`](crate::prelude::KeyPairHandle::sign_data)
    /// * [`KeyPairHandle::verify_signature`](crate::prelude::KeyPairHandle::verify_signature)
    /// * [`KeyPairHandle::encrypt_data()`](crate::prelude::KeyPairHandle::encrypt_data)
    /// * [`KeyPairHandle::decrypt_data()`](crate::prelude::KeyPairHandle::decrypt_data)
    pub supported_hashes: HashSet<CryptoHash>,

    /// Asymmetric cryptographic algorithms supported or required.
    ///
    /// A provider supporting an asymmetric cryptographic algorithm **may or may not** support said algorithm for signing or encryption operations.
    pub supported_asym_spec: HashSet<AsymmetricKeySpec>,
}

/// Key metadata store configuration
///
/// Due to an accident, this configuration became a vector.
///
/// If neither [`AdditionalConfig::KVStoreConfig`] nor [`AdditionalConfig::FileStoreConfig`] are supplied
/// to [`create_provider()`] or to [`create_provider_from_name()`],
/// a provider will be created that is only capable of creating ephemeral keys!
///
/// To protect key metadata against unauthorized change, it is recommended to make use of
/// [`AdditionalConfig::StorageConfigHMAC`] or [`AdditionalConfig::StorageConfigDSA`].
/// (This may only apply if you use multiple providers and one is of [`SecurityLevel::Hardware`] or above.)
///
/// If the fallback software provider is used with [AdditionalConfig::StorageConfigSymmetricEncryption]
/// or [AdditionalConfig::StorageConfigAsymmetricEncryption], the stored secret keys are secured by
/// the provided key, which in turn makes such construct a hybrid provider (as the keys at rest have hardware security protection).
///
///
/// ## Example
///
/// ```rust
/// # use crypto_layer::prelude::*;
///
/// let implementation_config = ProviderImplConfig {
///       additional_config: vec![
///          AdditionalConfig::FileStoreConfig {
///              db_dir: "./testdb".to_owned(),
///          }
///      ],
/// };
/// ```
///
/// [`create_provider()`]: crate::prelude::create_provider
/// [`create_provider_from_name()`]: crate::prelude::create_provider_from_name
///
// flutter_rust_bridge:non_opaque
#[derive(Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct ProviderImplConfig {
    pub additional_config: Vec<AdditionalConfig>,
}

/// Key metadata store configuration enumeration.
// flutter_rust_bridge:non_opaque
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
    /// Mutually exclusive with [AdditionalConfig::FileStoreConfig].
    KVStoreConfig {
        get_fn: GetFn,
        store_fn: StoreFn,
        delete_fn: DeleteFn,
        all_keys_fn: AllKeysFn,
    },

    /// Configuration for the usage of the metadata file database.
    ///
    /// Mutually exclusive with [AdditionalConfig::KVStoreConfig].
    FileStoreConfig {
        /// Path to a directory where the database holding key metadata will be saved.
        db_dir: String,
    },

    /// Enables integrity verification of key metadata.
    ///
    /// Mutually exclusive with [AdditionalConfig::StorageConfigDSA].
    StorageConfigHMAC(KeyHandle),

    /// Enables integrity verification of key metadata.
    ///
    /// Mutually exclusive with [AdditionalConfig::StorageConfigHMAC].
    StorageConfigDSA(KeyPairHandle),

    /// Enables encryption of sensitive key metadata.
    ///
    /// In case of the software provider, this enables encryption of secret keys.
    ///
    /// Mutually exclusive with [AdditionalConfig::StorageConfigAsymmetricEncryption].
    StorageConfigSymmetricEncryption(KeyHandle),

    /// Enables encryption of sensitive key metadata.
    ///
    /// In case of the software provider, this enables encryption of secret keys.
    ///
    /// Mutually exclusive with [AdditionalConfig::StorageConfigSymmetricEncryption].
    StorageConfigAsymmetricEncryption(KeyPairHandle),
}

impl std::fmt::Debug for ProviderImplConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderImplConfig{opaque}").finish()
    }
}

impl ProviderImplConfig {
    /// Creates a new `ProviderImplConfig` instance.
    #[doc(hidden)]
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

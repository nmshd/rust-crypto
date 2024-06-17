use crate::common::crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers};
use crate::common::crypto::algorithms::hashes::Hash;
use crate::common::crypto::KeyUsage;
use crate::common::traits::module_provider_config::ProviderConfig;
use std::any::Any;
use std::sync::Arc;

#[cfg(feature = "core")]
pub mod core;
#[cfg(feature = "hcvault")]
pub mod hcvault;

/// Configuration for NKS (Network Key Storage).
#[derive(Debug, Clone)]
pub struct NksConfig {
    /// The NKS token used for authentication.
    pub nks_token: String,
    /// The address of the Nks server.
    pub nks_address: String,
    /// The algorithm used for asymmetric encryption.
    pub key_algorithm: Option<AsymmetricEncryption>,
    /// The hash algorithm to be used.
    pub hash: Hash,
    /// A list of key usages specifying the intended use of the keys.
    pub key_usages: Vec<KeyUsage>,
    pub key_algorithm_sym: Option<BlockCiphers>,
}

impl ProviderConfig for NksConfig {
    /// Returns a reference to `self` as a trait object.
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl NksConfig {
    /// Creates a new `NksConfig` instance wrapped in an `Arc`.
    ///
    /// # Parameters
    /// - `nks_token`: A string representing the NKS token.
    /// - `nks_address`: A string representing the address of the NKS server.
    /// - `key_algorithm`: The asymmetric encryption algorithm to be used.
    /// - `hash`: The hash algorithm to be used.
    /// - `key_usages`: A vector of `KeyUsage` enums specifying the intended use of the keys.
    ///
    /// # Returns
    /// An `Arc` containing the `NksConfig` instance.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        nks_token: String,
        nks_address: String,
        key_algorithm_asym: Option<AsymmetricEncryption>,
        hash: Hash,
        key_usages: Vec<KeyUsage>,
        key_algorithm_sym: Option<BlockCiphers>,
    ) -> Arc<dyn ProviderConfig + Send + Sync> {
        Arc::new(Self {
            nks_token,
            nks_address,
            key_algorithm: key_algorithm_asym,
            hash,
            key_usages,
            key_algorithm_sym,
        })
    }
}

//TODO use CAL once it can compile
// use crate::common::crypto::{
//     algorithms::{
//         encryption::{
//             AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm, SymmetricMode,
//         },
//         hashes::{Hash, Sha2Bits, Sha3Bits},
//         KeyBits,
//     },
//     KeyUsage,
// };
use std::sync::Arc;

use crate::common::traits::module_provider_config::ProviderConfig;

pub mod key_handle;
pub mod provider;

/// A nks-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations.
///
/// This provider leverages the Network Key Storage (nks) to interact with a network
/// module for operations like signing, encryption, and decryption. It provides a secure and
/// network-backed implementation of cryptographic operations.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct NksProvider {
    //TODO implement NksProvider struct

    /// A unique identifier for the cryptographic key managed by this provider.
    key_id: String,
    pub(crate) config: Option<Arc<dyn ProviderConfig + Sync + Send>>,
    pub(super) secrets_json: Option<serde_json::Value>,
    public_key: String,
    private_key: String,
}

impl NksProvider {
    /// Constructs a new `NksProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    /// * `config` - The configuration for the NksProvider.
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            config: None,
            secrets_json: None,
            public_key: String::new(),
            private_key: String::new(),
        }
    }
}
use std::sync::Arc;

use crate::common::crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage};
use crate::hsm::yubikey;
use crate::hsm::ProviderConfig;
use tracing::instrument;

use yubikey::{piv::RetiredSlotId, YubiKey};

pub mod key_handle;
pub mod provider;

/// A YubiKey-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations.
///
/// This provider leverages the YubiKey API to interact with a YubiKey device for operations
/// like signing, encryption, and decryption. It provides a secure and hardware-backed solution
/// for managing cryptographic keys and performing cryptographic operations.

// #[derive(cloe, Debug)]???
#[derive(Debug)]
pub struct YubiKeyProvider {
    /// A unique identifier for the cryptographic key managed by this provider.
    pub(super) key_id: String,
    pub(super) pkey: Option<String>,
    pub(super) config: Option<Arc<dyn ProviderConfig + Sync + Send>>,
    pub(super) slot_id: Option<RetiredSlotId>,
    pub(super) key_usages: Option<Vec<KeyUsage>>,
    pub(super) key_algo: Option<AsymmetricEncryption>,
    pub(super) yubikey: Option<YubiKey>,
}

impl YubiKeyProvider {
    /// Constructs a new `YubiKeyProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    ///
    /// # Returns
    ///
    /// A new instance of `YubiKeyProvider` with the specified `key_id`.
    #[instrument]
    pub fn new(key_id: String) -> Self {
        Self {
            yubikey: None,
            key_id,
            pkey: None,
            config: None,
            slot_id: None,
            key_usages: None,
            key_algo: None,
        }
    }
    /*
        pub struct KeyHandle {
            pub (super) yubikey: YubiKey,
            pub (super) key_algorithm: String,
            pub (super) pkey: String,
        }

        impl KeyHandle for YubiKeyProvider {

            #[instrument]
            fn new(yubikey: YubiKey, key_algorithm: String, pkey: String) -> Self {
                Self {
                    key_id,
                    yubikey: None,
                    key_algorithm: None,
                    key_usages: None,
                    slot_id: None,
                    pkey: None,
                }
            }
        // Add YubiKey specific methods here
    }
    */
}

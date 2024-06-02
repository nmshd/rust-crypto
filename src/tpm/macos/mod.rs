use crate::common::crypto::{
    algorithms::{
        encryption::{AsymmetricEncryption, BlockCiphers, EccSchemeAlgorithm},
        hashes::{Hash, Sha2Bits},
    },
    KeyUsage,
};

use tracing::instrument;

pub mod key_handle;
pub mod provider;
pub mod logger; 

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpmProvider {
    key_id: String,
    // pub(super) key_handle: Option<String>, // Was ist mit key_handle gemeint? 
    // pub(super) handle: Option<String>, // Was ist mit handle gemeint? 
    pub(super) key_algorithm: Option<AsymmetricEncryption>,
    pub(super) sym_algorithm: Option<BlockCiphers>,
    pub(super) hash: Option<Hash>,
    pub(super) key_usages: Option<Vec<KeyUsage>>,

}

impl TpmProvider {

    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            // key_handle: None,
            // handle: None,
            key_algorithm: None,
            sym_algorithm: None,
            hash: None,
            key_usages: None,
        }
    }
}
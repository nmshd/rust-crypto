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

#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpmProvider {}

impl TpmProvider {
    #[instrument]
    pub fn new(key_id: String) -> Self {
        todo!();
    }
}

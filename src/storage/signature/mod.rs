use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use thiserror::Error;

use crate::prelude::{AdditionalConfig, CalError};
use crate::storage::signature::dsa::DsaBackend;
use crate::storage::signature::hmac::HmacBackend;
use crate::storage::signature::none::NoneBackend;
use crate::storage::{SignedData, StorageManagerError};

mod dsa;
mod hmac;
mod none;

#[derive(Debug, Error)]
pub enum SignatureBackendError {
    #[error("Failed to sign data.")]
    Sign { source: CalError },
    #[error("Error occurred during verifying signature.")]
    DuringVerify { source: CalError },
    #[error("Data failed to be verified by signature.")]
    Verify,
    #[error("Wrong signature type. Cannot verify such signature with this signature backend.")]
    WrongSignatureType,
    #[error("Failed to get scope.")]
    Scope { source: CalError },
}

#[enum_dispatch]
pub trait SignatureBackend {
    fn verify(&self, signed_data: SignedData) -> Result<Vec<u8>, SignatureBackendError>;

    fn sign(&self, data: Vec<u8>) -> Result<SignedData, SignatureBackendError>;

    fn scope(&self) -> Result<String, SignatureBackendError>;
}

#[enum_dispatch(SignatureBackend)]
#[derive(Debug, Clone)]
pub enum SignatureBackendExplicit {
    DsaBackend,
    HmacBackend,
    NoneBackend,
}

impl SignatureBackendExplicit {
    pub fn new(config: &[AdditionalConfig]) -> Result<Self, StorageManagerError> {
        Ok(config
            .iter()
            .filter_map(|e| match e {
                AdditionalConfig::StorageConfigHMAC(handle) => {
                    Some(Self::from(HmacBackend::new(handle.clone())))
                }
                AdditionalConfig::StorageConfigDSA(handle) => {
                    Some(Self::from(DsaBackend::new(handle.clone())))
                }
                _ => None,
            })
            .at_most_one()
            .map_err(|_| StorageManagerError::ConflictingProviderImplConfig {
                description: "Expected either StorageConfigHMAC OR StorageConfigDSA, not both.",
            })?
            .unwrap_or_else(|| Self::from(NoneBackend {})))
    }
}

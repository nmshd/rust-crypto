use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::prelude::{AdditionalConfig, CalError, ProviderImplConfig};
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
}

#[enum_dispatch]
pub trait SignatureBackend {
    fn verify(&self, signed_data: SignedData) -> Result<(), SignatureBackendError>;

    fn sign(&self, data: Vec<u8>) -> Result<SignedData, SignatureBackendError>;
}

#[enum_dispatch(SignatureBackend)]
#[derive(Debug, Clone)]
pub enum SignatureBackendExplicit {
    DsaBackend,
    HmacBackend,
    NoneBackend,
}

impl SignatureBackendExplicit {
    pub fn new(provider_impl_config: &ProviderImplConfig) -> Result<Self, StorageManagerError> {
        let mut encryption_backends =
            provider_impl_config
                .additional_config
                .iter()
                .filter_map(|e| match e {
                    AdditionalConfig::StorageConfigHMAC(handle) => {
                        Some(Self::from(HmacBackend::new(handle.clone())))
                    }
                    AdditionalConfig::StorageConfigDSA(handle) => {
                        Some(Self::from(DsaBackend::new(handle.clone())))
                    }
                    _ => None,
                });

        let encryption_backend = encryption_backends
            .next()
            .unwrap_or_else(|| Self::from(NoneBackend {}));

        if encryption_backends.next().is_some() {
            Err(StorageManagerError::ConflictingProviderImplConfig { description: "Expected either StorageConfigSymmetricEncryption OR StorageConfigAsymmetricEncryption, not both." })
        } else {
            Ok(encryption_backend)
        }
    }
}

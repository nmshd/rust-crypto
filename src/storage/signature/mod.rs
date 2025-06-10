use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::prelude::CalError;
use crate::storage::signature::dsa::DsaBackend;
use crate::storage::signature::hmac::HmacBackend;
use crate::storage::signature::none::NoneBackend;
use crate::storage::SignedData;

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

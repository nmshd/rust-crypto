use crate::storage::{signature::SignatureBackend, Signature, SignedData};

use super::SignatureBackendError;

#[derive(Clone, Debug)]
pub struct NoneBackend {}

impl SignatureBackend for NoneBackend {
    fn sign(&self, data: Vec<u8>) -> Result<crate::storage::SignedData, SignatureBackendError> {
        Ok(SignedData {
            data,
            signature: Signature::None,
        })
    }

    fn verify(&self, signed_data: SignedData) -> Result<Vec<u8>, SignatureBackendError> {
        if matches!(signed_data.signature, Signature::None) {
            Ok(signed_data.data)
        } else {
            Err(SignatureBackendError::WrongSignatureType)
        }
    }

    fn scope(&self) -> Result<String, SignatureBackendError> {
        Ok("NONE".to_owned())
    }
}

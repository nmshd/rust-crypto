use std::sync::Arc;

use crate::{
    common::KeyHandle,
    storage::{
        signature::{SignatureBackend, SignatureBackendError},
        Signature, SignedData,
    },
};

#[derive(Clone, Debug)]
pub struct HmacBackend {
    handle: Arc<KeyHandle>,
}

impl HmacBackend {
    pub fn new(key_handle: KeyHandle) -> Self {
        Self {
            handle: Arc::new(key_handle),
        }
    }
}

impl SignatureBackend for HmacBackend {
    fn sign(&self, data: Vec<u8>) -> Result<SignedData, super::SignatureBackendError> {
        let signature = self
            .handle
            .hmac(&data)
            .map_err(|e| SignatureBackendError::Sign { source: e })?;

        Ok(SignedData {
            data,
            signature: Signature::HMAC(signature),
        })
    }

    fn verify(&self, signed_data: SignedData) -> Result<Vec<u8>, SignatureBackendError> {
        match signed_data.signature {
            Signature::HMAC(signature) => {
                if self
                    .handle
                    .verify_hmac(&signed_data.data, &signature)
                    .map_err(|e| SignatureBackendError::DuringVerify { source: e })?
                {
                    Ok(signed_data.data)
                } else {
                    Err(SignatureBackendError::Verify)
                }
            }
            _ => Err(SignatureBackendError::WrongSignatureType),
        }
    }

    fn scope(&self) -> Result<String, SignatureBackendError> {
        self.handle
            .id()
            .map_err(|e| SignatureBackendError::Scope { source: e })
    }
}

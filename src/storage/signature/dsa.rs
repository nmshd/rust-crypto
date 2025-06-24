use std::sync::Arc;

use crate::{
    common::KeyPairHandle,
    storage::{
        signature::{SignatureBackend, SignatureBackendError},
        Signature, SignedData,
    },
};

#[derive(Clone, Debug)]
pub struct DsaBackend {
    handle: Arc<KeyPairHandle>,
}

impl DsaBackend {
    pub fn new(key_pair_handle: KeyPairHandle) -> Self {
        Self {
            handle: Arc::new(key_pair_handle),
        }
    }
}

impl SignatureBackend for DsaBackend {
    fn sign(
        &self,
        data: Vec<u8>,
    ) -> Result<crate::storage::SignedData, super::SignatureBackendError> {
        let signature = self
            .handle
            .sign_data(&data)
            .map_err(|e| SignatureBackendError::Sign { source: e })?;

        Ok(SignedData {
            data,
            signature: Signature::DSA(signature),
        })
    }

    fn verify(&self, signed_data: SignedData) -> Result<Vec<u8>, SignatureBackendError> {
        match signed_data.signature {
            Signature::DSA(signature) => {
                if self
                    .handle
                    .verify_signature(&signed_data.data, &signature)
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

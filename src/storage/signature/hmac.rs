use crate::{
    common::KeyHandle,
    storage::{
        signature::{SignatureBackend, SignatureBackendError},
        Signature, SignedData,
    },
};

pub struct HmacBackend {
    handle: KeyHandle,
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

    fn verify(&self, signed_data: SignedData) -> Result<(), SignatureBackendError> {
        match signed_data.signature {
            Signature::HMAC(signature) => {
                if self
                    .handle
                    .verify_hmac(&signed_data.data, &signature)
                    .map_err(|e| SignatureBackendError::DuringVerify { source: e })?
                {
                    Ok(())
                } else {
                    Err(SignatureBackendError::Verify)
                }
            }
            _ => Err(SignatureBackendError::WrongSignatureType),
        }
    }
}

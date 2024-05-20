use super::TpmProvider;
use crate::common::{
    crypto::algorithms::encryption::AsymmetricEncryption, error::SecurityModuleError,
    traits::key_handle::KeyHandle,
};
use tracing::instrument;
use tss_esapi::{
    interface_types::{algorithm::SymmetricMode, resource_handles::Hierarchy},
    structures::{
        Data, EccParameter, EccSignature, HashScheme, InitialValue, MaxBuffer, PublicKeyRsa,
        RsaDecryptionScheme, RsaSignature, Signature, SignatureScheme,
    },
    traits::Marshall,
};

impl KeyHandle for TpmProvider {
    /// Signs the given data using the cryptographic key managed by the TPM provider.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let key_handle = *self.key_handle.as_ref().unwrap().lock().unwrap();
        let ticket = self
            .handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .hash(
                MaxBuffer::try_from(data).unwrap(),
                self.hash.unwrap().into(),
                Hierarchy::Null,
            )
            .map_err(|e| SecurityModuleError::SigningError(e.to_string()))?;

        let signature = match self.key_algorithm.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => self
                .handle
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .sign(
                    key_handle,
                    ticket.0,
                    SignatureScheme::RsaSsa {
                        hash_scheme: HashScheme::new(self.hash.unwrap().into()),
                    },
                    ticket.1,
                )
                .map_err(|e| SecurityModuleError::SigningError(e.to_string()))?,
            AsymmetricEncryption::Ecc(ecc_scheme) => {
                let signature_scheme: SignatureScheme = (*ecc_scheme).into();
                self.handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .sign(key_handle, ticket.0, signature_scheme, ticket.1)
                    .map_err(|e| SecurityModuleError::SigningError(e.to_string()))?
            }
        };

        signature
            .marshall()
            .map_err(|e| SecurityModuleError::SigningError(e.to_string()))
    }

    /// Decrypts the given encrypted data using the cryptographic key managed by the TPM provider.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let key_handle = *self.key_handle.as_ref().unwrap().lock().unwrap();

        match self.key_algorithm.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => {
                let scheme =
                    RsaDecryptionScheme::Oaep(HashScheme::new(self.hash.unwrap().into()));
                let pub_key = PublicKeyRsa::try_from(encrypted_data)
                    .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?;
                let decryption_result = self
                    .handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .rsa_decrypt(
                        key_handle,
                        pub_key,
                        scheme,
                        Data::try_from(encrypted_data)
                            .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?,
                    )
                    .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?;
                Ok(decryption_result.to_vec())
            }
            AsymmetricEncryption::Ecc(_) => {
                let initial_value = InitialValue::try_from(vec![0u8; 16])
                    .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?;
                let (decrypted_data, _) = self
                    .handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .encrypt_decrypt_2(
                        key_handle,
                        true,
                        SymmetricMode::Cfb,
                        MaxBuffer::try_from(encrypted_data)
                            .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?,
                        initial_value,
                    )
                    .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?;
                Ok(decrypted_data.to_vec())
            }
        }
    }

    /// Encrypts the given data using the cryptographic key managed by the TPM provider.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let key_handle = *self.key_handle.as_ref().unwrap().lock().unwrap();

        match self.key_algorithm.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => {
                let scheme =
                    RsaDecryptionScheme::Oaep(HashScheme::new(self.hash.unwrap().into()));
                let message = PublicKeyRsa::try_from(data)
                    .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?;
                let encryption_result = self
                    .handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .rsa_encrypt(
                        key_handle,
                        message,
                        scheme,
                        Data::try_from(data)
                            .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?,
                    )
                    .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?;
                Ok(encryption_result.value().to_vec())
            }
            AsymmetricEncryption::Ecc(_) => {
                let initial_value = InitialValue::try_from(vec![0u8; 16])
                    .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?;
                let (encrypted_data, _) = self
                    .handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .encrypt_decrypt_2(
                        key_handle,
                        false,
                        SymmetricMode::Cfb,
                        MaxBuffer::try_from(data)
                            .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?,
                        initial_value,
                    )
                    .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?;
                Ok(encrypted_data.to_vec())
            }
        }
    }

    /// Verifies the signature of the given data using the cryptographic key managed by the TPM provider.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data whose signature is to be verified.
    /// * `signature` - A byte slice representing the signature to be verified against the data.
    ///
    /// # Returns
    ///
    /// A `Result` containing a boolean indicating whether the signature is valid (`true`) or not (`false`),
    /// or a `SecurityModuleError` on failure.
    #[instrument]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        let key_handle = *self.key_handle.as_ref().unwrap().lock().unwrap();
        let digest = self
            .handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .hash(
                MaxBuffer::try_from(data).unwrap(),
                self.hash.unwrap().into(),
                Hierarchy::Null,
            )
            .map_err(|e| SecurityModuleError::SignatureVerificationError(e.to_string()))?
            .0;

        let verification_result = match self.key_algorithm.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => {
                let signature = PublicKeyRsa::try_from(signature)
                    .map_err(|e| SecurityModuleError::SignatureVerificationError(e.to_string()))?;
                let rsa_signature =
                    RsaSignature::create(self.hash.unwrap().into(), signature).map_err(
                        |e| SecurityModuleError::SignatureVerificationError(e.to_string()),
                    )?;
                self.handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .verify_signature(key_handle, digest, Signature::RsaSsa(rsa_signature))
                    .is_ok()
            }
            AsymmetricEncryption::Ecc(ecc_scheme) => {
                let signature_scheme: SignatureScheme = (*ecc_scheme).into();
                let (signature_r, signature_s) = match signature.split_at(signature.len() / 2) {
                    (&[], &[]) => {
                        return Err(SecurityModuleError::SignatureVerificationError(
                            "Invalid signature length".to_string(),
                        ))
                    }
                    (r, s) => (
                        EccParameter::try_from(r).map_err(|e| {
                            SecurityModuleError::SignatureVerificationError(e.to_string())
                        })?,
                        EccParameter::try_from(s).map_err(|e| {
                            SecurityModuleError::SignatureVerificationError(e.to_string())
                        })?,
                    ),
                };
                let ecc_signature = EccSignature::create(
                    self.hash.unwrap().into(),
                    signature_r,
                    signature_s,
                )
                .map_err(|e| SecurityModuleError::SignatureVerificationError(e.to_string()))?;
                let signature = match signature_scheme {
                    SignatureScheme::EcDsa { .. } => Signature::EcDsa(ecc_signature),
                    SignatureScheme::EcDaa { .. } => Signature::EcDaa(ecc_signature),
                    SignatureScheme::Sm2 { .. } => Signature::Sm2(ecc_signature),
                    SignatureScheme::EcSchnorr { .. } => Signature::EcSchnorr(ecc_signature),
                    _ => unreachable!(),
                };
                self.handle
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .verify_signature(key_handle, digest, signature)
                    .is_ok()
            }
        };

        Ok(verification_result)
    }
}

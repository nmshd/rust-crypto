use super::TpmProvider;
use crate::common::{
    crypto::algorithms::encryption::AsymmetricEncryption, error::SecurityModuleError,
    traits::key_handle::KeyHandle,
};
use tracing::instrument;
use tss_esapi::{
    attributes::SessionAttributes,
    constants::SessionType,
    handles::ObjectHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        resource_handles::Hierarchy,
    },
    structures::{
        Auth, Data, EccParameter, EccSignature, HashScheme, InitialValue, MaxBuffer, PublicBuilder,
        PublicKeyRsa, PublicRsaParametersBuilder, RsaDecryptionScheme, RsaSignature, Signature,
        SignatureScheme, SymmetricDefinition,
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
            .provider_handle
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
                .provider_handle
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
                self.provider_handle
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
                let scheme = RsaDecryptionScheme::Oaep(HashScheme::new(self.hash.unwrap().into()));
                let pub_key = PublicKeyRsa::try_from(encrypted_data)
                    .map_err(|e| SecurityModuleError::DecryptionError(e.to_string()))?;
                let decryption_result = self
                    .provider_handle
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
                    .provider_handle
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
                let scheme = RsaDecryptionScheme::Oaep(HashScheme::new(self.hash.unwrap().into()));
                let message = PublicKeyRsa::try_from(data)
                    .map_err(|e| SecurityModuleError::EncryptionError(e.to_string()))?;
                let encryption_result = self
                    .provider_handle
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
                    .provider_handle
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
            .provider_handle
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
                let rsa_signature = RsaSignature::create(self.hash.unwrap().into(), signature)
                    .map_err(|e| SecurityModuleError::SignatureVerificationError(e.to_string()))?;
                self.provider_handle
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

                let ecc_signature =
                    EccSignature::create(self.hash.unwrap().into(), signature_r, signature_s)
                        .map_err(|e| {
                            SecurityModuleError::SignatureVerificationError(e.to_string())
                        })?;

                let signature = match signature_scheme {
                    SignatureScheme::EcDsa { .. } => Signature::EcDsa(ecc_signature),
                    SignatureScheme::EcDaa { .. } => Signature::EcDaa(ecc_signature),
                    SignatureScheme::Sm2 { .. } => Signature::Sm2(ecc_signature),
                    SignatureScheme::EcSchnorr { .. } => Signature::EcSchnorr(ecc_signature),
                    _ => unreachable!(),
                };

                self.provider_handle
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

    #[doc = " TODO: Docs"]
    #[doc = " # Returns"]
    #[doc = " A `Result` containing the new key id on success or a `SecurityModuleError` on failure."]
    fn derive_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        // Start an authentication session
        let session = self
            .provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .unwrap();

        // Set session attributes
        let session_attributes = SessionAttributes::builder()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();

        self.provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .tr_sess_set_attributes(session.unwrap(), session_attributes.0, session_attributes.1)
            .unwrap();

        // Set the password for the primary key
        let primary_key_handle = *self.key_handle.as_ref().unwrap().lock().unwrap();

        self.provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .tr_set_auth(ObjectHandle::from(primary_key_handle), Auth::default())
            .unwrap();

        // Define the attributes of the derived key
        let derived_key_public = PublicBuilder::new()
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(tss_esapi::attributes::ObjectAttributes(
                tss_esapi::constants::tss::TPMA_OBJECT_DECRYPT
                    | tss_esapi::constants::tss::TPMA_OBJECT_SIGN_ENCRYPT
                    | tss_esapi::constants::tss::TPMA_OBJECT_SENSITIVEDATAORIGIN
                    | tss_esapi::constants::tss::TPMA_OBJECT_USERWITHAUTH,
            ))
            .with_rsa_parameters(PublicRsaParametersBuilder::new().build().unwrap())
            .build()
            .unwrap();

        // Create the derived key
        let derived_key_result = self
            .provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .create(
                *self.key_handle.as_ref().unwrap().lock().unwrap(),
                derived_key_public,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        Ok(derived_key_result.out_private.to_vec())
    }

    #[doc = " TODO: Docs"]
    #[doc = " # Returns"]
    #[doc = " A `Result` containing the new key on success or a `SecurityModuleError` on failure."]
    fn generate_exchange_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), SecurityModuleError> {
        let result = self
            .provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .ecdh_key_gen(*self.key_handle.as_ref().unwrap().lock().unwrap())
            .unwrap();

        let mut vec0 = result.0.x().to_vec();
        vec0.append(&mut result.0.y().to_vec());

        let mut vec1 = result.1.x().to_vec();
        vec1.append(&mut result.1.y().to_vec());

        Ok((vec0, vec1))
    }
}

use crate::common::{
    config::{KeyPairSpec, KeySpec},
    crypto::algorithms::encryption::AsymmetricKeySpec,
    error::CalError,
    traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
    DHExchange,
};
use ring::{
    aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, Signature, UnparsedPublicKey},
};
use std::sync::Arc;
use tracing::warn;

use super::StorageManager;

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) signing_key: Option<Vec<u8>>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) storage_manager: StorageManager,
}

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyHandle {
    pub(crate) key_id: String,
    pub(crate) key: Arc<LessSafeKey>,
    pub(crate) storage_manager: StorageManager,
}

impl SoftwareKeyHandle {
    pub fn new(
        key_id: String,
        spec: Option<KeySpec>,
        key_data: Vec<u8>,
        storage_manager: StorageManager,
    ) -> Result<Self, CalError> {
        // Create the AES key for encryption and decryption
        let algo: &Algorithm = spec.as_ref().unwrap().cipher.into();
        let unbound_key = UnboundKey::new(algo, &key_data).expect("Failed to create AES key");
        let key = Arc::new(LessSafeKey::new(unbound_key));

        Ok(Self {
            key_id,
            key,
            storage_manager,
        })
    }
}

impl KeyHandleImpl for SoftwareKeyHandle {
    fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, std::vec::Vec<u8>), CalError> {
        let rng = SystemRandom::new();

        // Generate a unique nonce for this encryption operation
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .expect("Failed to generate nonce");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Prepare additional associated data (AAD), here as an empty slice
        let aad = Aad::empty();

        // Copy the plaintext data and prepare for encryption
        let mut in_out = data.to_vec();
        in_out.extend(vec![0u8; 16]); // Reserve space for the authentication tag

        // Perform encryption
        self.key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .expect("Encryption failed");

        // Prepend the nonce to the ciphertext
        let mut encrypted_data = nonce_bytes.to_vec();
        encrypted_data.extend(&in_out);

        Ok((encrypted_data, vec![]))
    }

    fn decrypt_data(&self, encrypted_data: &[u8], _iv: &[u8]) -> Result<Vec<u8>, CalError> {
        // Separate nonce and ciphertext
        if encrypted_data.len() <= NONCE_LEN {
            return Err(CalError::failed_operation(
                "Data too short".to_string(),
                true,
                None,
            ));
        }
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_LEN);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

        // Prepare AAD as an empty slice
        let aad = Aad::empty();

        // Copy the ciphertext for in-place decryption
        let mut in_out = ciphertext.to_vec();

        // Perform decryption
        self.key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;

        // Remove the authentication tag
        in_out.truncate(in_out.len() - 16);
        Ok(in_out)
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        todo!("Cannot extract symmetric keys")
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key."]
    fn delete(self) -> Result<(), CalError> {
        self.storage_manager.delete(self.key_id);
        Ok(())
    }
}

impl KeyPairHandleImpl for SoftwareKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        let signing_key = match self.signing_key.as_ref() {
            Some(key) => key,
            None => {
                return Err(CalError::failed_operation(
                    "No private key available for signing".to_string(),
                    true,
                    None,
                ))
            }
        };

        match self.spec.asym_spec {
            AsymmetricKeySpec::Ecc { curve, .. } => match curve {
                EccCurve::Curve25519 => ed25519_compact::SecretKey::from_slice(&signing_key)
                    .map(|key| {
                        key.sign(data, Some(ed25519_compact::Noise::generate()))
                            .to_vec()
                    })
                    .map_err(|_| {
                        CalError::failed_operation(
                            "Failed to use signing key".to_string(),
                            true,
                            None,
                        )
                    }),
                EccCurve::P256 | EccCurve::P384 => {
                    // Secure random generator for signing
                    let rng = SystemRandom::new();

                    let signing_key = EcdsaKeyPair::from_pkcs8(
                        self.spec.asym_spec.into(),
                        signing_key.as_slice(),
                        &rng,
                    )
                    .map_err(|_| {
                        CalError::failed_operation(
                            "Failed to use signing key".to_string(),
                            true,
                            None,
                        )
                    })?;

                    // Sign the data
                    let signature: Signature = signing_key.sign(&rng, data).map_err(|_| {
                        CalError::failed_operation(
                            "Failed to use signing key".to_string(),
                            true,
                            None,
                        )
                    })?;

                    Ok(signature.as_ref().to_vec())
                }
                _ => todo!(),
            },
            _ => todo!(),
        }
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        warn!("Verifying signature");
        match self.spec.asym_spec {
            AsymmetricKeySpec::Ecc { curve, .. } => match curve {
                EccCurve::Curve25519 => {
                    ed25519_compact::PublicKey::from_slice(self.public_key.as_slice())
                        .and_then(|key| {
                            ed25519_compact::Signature::from_slice(signature)
                                .map(|signature| (key, signature))
                        })
                        .map(|(key, signature)| key.verify(data, &signature).is_ok())
                        .map_err(|_| {
                            CalError::failed_operation(
                                "Failed to use public key".to_string(),
                                true,
                                None,
                            )
                        })
                }
                EccCurve::P256 | EccCurve::P384 => {
                    // Create an UnparsedPublicKey using the algorithm and the public key bytes
                    Ok(
                        UnparsedPublicKey::new(self.spec.asym_spec.into(), &self.public_key)
                            .verify(data, signature)
                            .inspect_err(|e| warn!("Failed to verify signature: {e:?}"))
                            .is_ok(),
                    )
                }
                _ => todo!(),
            },
            _ => todo!(),
        }
    }

    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Encryption not supported for ECC keys")
    }

    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Decryption not supported for ECC keys")
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.clone())
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.clone())
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        todo!("DH exchange not supported")
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key pair."]
    fn delete(self) -> Result<(), CalError> {
        self.storage_manager.delete(self.key_id);
        Ok(())
    }
}

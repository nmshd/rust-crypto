use crate::{
    common::{
        config::{KeyPairSpec, KeySpec},
        crypto::algorithms::encryption::AsymmetricKeySpec,
        error::CalError,
        traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
        DHExchange,
    },
    prelude::Cipher,
};
use chacha20poly1305::{
    aead::{Aead, OsRng},
    AeadCore, KeyInit, XChaCha20Poly1305, XNonce,
};
use ring::{
    aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, Signature, UnparsedPublicKey},
};
use tracing::warn;

use super::StorageManager;

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) signing_key: Option<Vec<u8>>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) storage_manager: Option<StorageManager>,
}

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyHandle {
    pub(crate) key_id: String,
    pub(crate) key: Vec<u8>,
    pub(crate) storage_manager: Option<StorageManager>,
    pub(crate) spec: KeySpec,
}

impl SoftwareKeyHandle {
    pub fn new(
        key_id: String,
        spec: KeySpec,
        key_data: Vec<u8>,
        storage_manager: Option<StorageManager>,
    ) -> Result<Self, CalError> {
        Ok(Self {
            key_id,
            key: key_data,
            storage_manager,
            spec,
        })
    }
}

impl KeyHandleImpl for SoftwareKeyHandle {
    fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        match self.spec.cipher {
            Cipher::XChaCha20Poly1305 => {
                let (nonce, ciphertext) =
                    encrypt_xchacha20poly1305(&self.key, data).map_err(|_| {
                        CalError::failed_operation("Encryption failed".to_owned(), true, None)
                    })?;
                Ok((ciphertext, nonce))
            }
            Cipher::AesGcm128 | Cipher::AesGcm256 => {
                let rng = SystemRandom::new();
                let mut nonce_bytes = [0u8; NONCE_LEN];
                rng.fill(&mut nonce_bytes).map_err(|_| {
                    CalError::failed_operation("Failed to generate nonce".to_owned(), true, None)
                })?;
                let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                let aad = Aad::empty();
                let mut in_out = data.to_vec();
                in_out.extend(vec![0u8; 16]);

                let algo: &Algorithm = self.spec.cipher.into();
                let unbound_key = UnboundKey::new(algo, &self.key).map_err(|_| {
                    CalError::failed_operation(
                        "Failed to create unbound AES key".to_owned(),
                        true,
                        None,
                    )
                })?;
                let key = LessSafeKey::new(unbound_key);

                key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                    .map_err(|_| {
                        CalError::failed_operation("Encryption failed".to_owned(), true, None)
                    })?;

                Ok((in_out, nonce_bytes.to_vec()))
            }
            _ => Err(CalError::failed_operation(
                "Unsupported cipher".to_owned(),
                true,
                None,
            )),
        }
    }

    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        match self.spec.cipher {
            Cipher::XChaCha20Poly1305 => decrypt_xchacha20poly1305(&self.key, iv, encrypted_data)
                .map_err(|_| {
                    CalError::failed_operation("Decryption failed".to_owned(), true, None)
                }),
            Cipher::AesGcm128 | Cipher::AesGcm256 => {
                if encrypted_data.len() <= NONCE_LEN + 16 {
                    return Err(CalError::failed_operation(
                        "Data too short".to_string(),
                        true,
                        None,
                    ));
                }

                let nonce = Nonce::assume_unique_for_key(iv.try_into().map_err(|_| {
                    CalError::failed_operation("Invalid nonce length".to_owned(), true, None)
                })?);

                let aad = Aad::empty();
                let mut in_out = encrypted_data.to_vec();

                let algo: &Algorithm = self.spec.cipher.into();
                let unbound_key = UnboundKey::new(algo, &self.key).map_err(|_| {
                    CalError::failed_operation(
                        "Failed to create unbound AES key".to_owned(),
                        true,
                        None,
                    )
                })?;
                let key = LessSafeKey::new(unbound_key);

                key.open_in_place(nonce, aad, &mut in_out)
                    .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;

                in_out.truncate(in_out.len() - 16);
                Ok(in_out)
            }
            _ => Err(CalError::failed_operation(
                "Unsupported cipher".to_owned(),
                true,
                None,
            )),
        }
    }

    fn hmac(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("HMAC not supported for AES keys")
    }

    fn verify_hmac(&self, _data: &[u8], _hmac: &[u8]) -> Result<bool, CalError> {
        todo!("HMAC not supported for AES keys")
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.key.clone())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key."]
    fn delete(self) -> Result<(), CalError> {
        if let Some(s) = self.storage_manager {
            s.delete(self.key_id)
        }
        Ok(())
    }
}

impl KeyPairHandleImpl for SoftwareKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        let Some(signing_key) = self.signing_key.as_ref() else {
            return Err(CalError::failed_operation(
                "No private key available for signing".to_string(),
                true,
                None,
            ));
        };

        match self.spec.asym_spec {
            AsymmetricKeySpec::Curve25519 => ed25519_compact::SecretKey::from_slice(signing_key)
                .map(|key| {
                    key.sign(data, Some(ed25519_compact::Noise::generate()))
                        .to_vec()
                })
                .map_err(|_| {
                    CalError::failed_operation("Failed to use signing key".to_string(), true, None)
                }),
            AsymmetricKeySpec::P256 | AsymmetricKeySpec::P384 => {
                // Secure random generator for signing
                let rng = SystemRandom::new();

                let signing_key = EcdsaKeyPair::from_pkcs8(
                    self.spec.asym_spec.into(),
                    signing_key.as_slice(),
                    &rng,
                )
                .map_err(|_| {
                    CalError::failed_operation("Failed to use signing key".to_string(), true, None)
                })?;

                // Sign the data
                let signature: Signature = signing_key.sign(&rng, data).map_err(|_| {
                    CalError::failed_operation("Failed to use signing key".to_string(), true, None)
                })?;

                Ok(signature.as_ref().to_vec())
            }
            _ => todo!(),
        }
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        warn!("Verifying signature");
        match self.spec.asym_spec {
            AsymmetricKeySpec::Curve25519 => {
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
            AsymmetricKeySpec::P256 | AsymmetricKeySpec::P384 => {
                // Create an UnparsedPublicKey using the algorithm and the public key bytes
                Ok(
                    UnparsedPublicKey::new(self.spec.asym_spec.into(), &self.public_key)
                        .verify(data, signature)
                        .inspect_err(|e| warn!("Failed to verify signature: {e:?}"))
                        .is_ok(),
                )
            }
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
        if !self.spec.non_exportable {
            Ok(self.signing_key.clone().unwrap())
        } else {
            Err(CalError::failed_operation(
                "The private key is not exportable".to_string(),
                true,
                None,
            ))
        }
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        todo!("DH exchange not supported")
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key pair."]
    fn delete(self) -> Result<(), CalError> {
        if let Some(s) = self.storage_manager {
            s.delete(self.key_id)
        }
        Ok(())
    }
}

fn encrypt_xchacha20poly1305(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;
    Ok((nonce.to_vec(), ciphertext))
}

fn decrypt_xchacha20poly1305(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CalError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;
    Ok(plaintext)
}

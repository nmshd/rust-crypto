use crate::{
    common::{
        config::{KeyPairSpec, KeySpec},
        crypto::algorithms::encryption::AsymmetricKeySpec,
        error::{CalError, KeyType},
        traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
        DHExchange, KeyHandle,
    },
    prelude::Cipher,
};
use anyhow::anyhow;
use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use ring::{
    aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, MAX_TAG_LEN, NONCE_LEN},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, Signature, UnparsedPublicKey},
};
use tracing::{error, instrument, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::StorageManager;

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) signing_key: Option<Vec<u8>>,
    pub(crate) public_key: Vec<u8>,
    pub(crate) storage_manager: Option<StorageManager>,
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SoftwareKeyHandle {
    pub(crate) key_id: String,
    pub(crate) key: Vec<u8>,
    #[zeroize(skip)]
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

/// Hashes and encodes a buffer to a string.
///
/// This is meant to generate deterministic ids from variable length nonces and contexts in derive key.
fn id_from_buffer(buff: &[u8]) -> Result<String, CalError> {
    // `digest` and `blake2` crate have both update functions that get each other int the way.
    use blake2::{Blake2b, Digest};
    use digest::consts::U8;

    type Blake2b64 = Blake2b<U8>;

    let mut hasher = Blake2b64::new();
    hasher.update(buff);
    let hash = hasher.finalize();
    let hash_vec = hash.to_vec();
    Ok(base64::prelude::BASE64_STANDARD.encode(hash_vec))
}

impl KeyHandleImpl for SoftwareKeyHandle {
    #[instrument(level = "trace")]
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        match self.spec.cipher {
            Cipher::AesGcm128 | Cipher::AesGcm256 => {
                let (nonce, nonce_bytes) = if !iv.is_empty() {
                    if iv.len() == NONCE_LEN {
                        let nonce_array: [u8; NONCE_LEN] =
                            iv.try_into().expect("Length already checked");
                        (Nonce::assume_unique_for_key(nonce_array), iv.to_vec())
                    } else {
                        return Err(CalError::failed_operation(
                            format!(
                                "Invalid IV length for AES-GCM: expected {} bytes, got {}",
                                NONCE_LEN,
                                iv.len()
                            ),
                            false,
                            None,
                        ));
                    }
                } else {
                    let rng = SystemRandom::new();
                    let mut generated_nonce_bytes = [0u8; NONCE_LEN];
                    rng.fill(&mut generated_nonce_bytes).map_err(|_| {
                        CalError::failed_operation(
                            "Failed to generate nonce".to_string(),
                            true,
                            None,
                        )
                    })?;
                    (
                        ring::aead::Nonce::assume_unique_for_key(generated_nonce_bytes),
                        generated_nonce_bytes.to_vec(),
                    )
                };

                let aad = Aad::empty();
                let mut in_out = data.to_vec();
                in_out.extend(vec![0u8; 16]);

                let algo: &Algorithm = self.spec.cipher.into();
                let unbound_key = UnboundKey::new(algo, &self.key).map_err(|e| {
                    CalError::failed_operation(
                        format!("Failed to create unbound AES key: {}", e),
                        true,
                        None,
                    )
                })?;
                let key = LessSafeKey::new(unbound_key);
                key.seal_in_place_append_tag(nonce, aad, &mut in_out)
                    .map_err(|_| {
                        CalError::failed_operation("Encryption failed".to_string(), true, None)
                    })?;

                Ok((in_out, nonce_bytes.to_vec()))
            }
            Cipher::XChaCha20Poly1305 => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&self.key);

                let nonce: [u8; 24] = if !iv.is_empty() {
                    if iv.len() == 24 {
                        iv.try_into().map_err(|_| {
                            CalError::failed_operation(
                                "Internal error converting IV slice to array".to_string(),
                                true,
                                None,
                            )
                        })?
                    } else {
                        return Err(CalError::failed_operation(
                            format!(
                                "Invalid IV length for XChaCha20: expected {} bytes, got {}",
                                24,
                                iv.len()
                            ),
                            false,
                            None,
                        ));
                    }
                } else {
                    let mut generated_bytes = [0u8; 24];
                    OsRng.fill_bytes(&mut generated_bytes);
                    generated_bytes
                };

                let cipher = XChaCha20Poly1305::new(&key.into());
                let ciphertext = cipher.encrypt((&nonce).into(), data).map_err(|e| {
                    CalError::failed_operation("failed encrypting", false, Some(anyhow!(e)))
                })?;

                Ok((ciphertext, nonce.to_vec()))
            }
            _ => Err(CalError::failed_operation(
                "Cipher not supported".to_string(),
                true,
                None,
            )),
        }
    }

    #[instrument(level = "trace")]
    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        match self.spec.cipher {
            Cipher::AesGcm128 | Cipher::AesGcm256 => {
                if encrypted_data.len() <= NONCE_LEN {
                    return Err(CalError::failed_operation(
                        "Data too short".to_string(),
                        true,
                        None,
                    ));
                }

                if iv.len() != NONCE_LEN {
                    error!(
                        iv = iv,
                        len = iv.len(),
                        expected = NONCE_LEN,
                        "Nonce for AES GCM must be 96bit long."
                    );
                    return Err(CalError::bad_parameter(
                        "Nonce for AES GCM must be 96bit long.".to_owned(),
                        true,
                        None,
                    ));
                }

                let nonce = Nonce::assume_unique_for_key(iv.try_into().unwrap());

                // Prepare AAD as an empty slice
                let aad = Aad::empty();

                // Copy the ciphertext for in-place decryption
                let mut in_out = encrypted_data.to_vec();

                let algo: &Algorithm = self.spec.cipher.into();

                // Create an UnboundKey for the AES-GCM encryption
                let unbound_key = UnboundKey::new(algo, &self.key).map_err(|err| {
                    CalError::failed_operation(
                        "Failed to create unbound AES key".to_owned(),
                        false,
                        Some(anyhow!(err)),
                    )
                })?;

                // Wrap it in a LessSafeKey for easier encryption/decryption
                let key = LessSafeKey::new(unbound_key);

                // Perform decryption
                key.open_in_place(nonce, aad, &mut in_out).map_err(|err| {
                    CalError::failed_operation(
                        "Failed decryption with ring".to_owned(),
                        false,
                        Some(anyhow!(err)),
                    )
                })?;

                // Remove the authentication tag
                in_out.truncate(in_out.len() - 16 - MAX_TAG_LEN);

                Ok(in_out)
            }

            Cipher::XChaCha20Poly1305 => {
                // Copy the key into a fixed-size array (32 bytes)
                let mut key = [0u8; 32];
                key.copy_from_slice(&self.key);

                // Create the cipher
                let cipher = XChaCha20Poly1305::new(&key.into());

                let result = cipher.decrypt(iv.into(), encrypted_data).map_err(|e| {
                    CalError::failed_operation("failed encrypting", false, Some(anyhow!(e)))
                })?;

                // No built-in authentication tag to remove, so the decrypted
                // plaintext is now in `buffer`.
                Ok(result)
            }

            // Fallback for any other ciphers you might define.
            _ => Err(CalError::failed_operation(
                "Cipher not supported".to_string(),
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

    fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError> {
        // `digest` and `blake2` crate have both update functions that get each other int the way.
        use blake2::Blake2bVar;
        use digest::{Update, VariableOutput};

        let mut spec = self.spec.clone();
        spec.ephemeral = true;
        let key_length = spec.cipher.len();

        let mut hasher = Blake2bVar::new(key_length).map_err(|e| {
            let cal_err = CalError::bad_parameter(
                "Blake2b failed to initialize".to_owned(),
                false,
                Some(anyhow!(e)),
            );
            error!(err = %cal_err, "Failed Blake2b init.");
            cal_err
        })?;

        hasher.update(nonce);
        hasher.update(&self.key);

        let mut derived_key = vec![0u8; key_length];

        hasher
            .finalize_variable(derived_key.as_mut_slice())
            .map_err(|e| {
                let cal_err = CalError::bad_parameter(
                    "Blake2b failed to write hash.".to_owned(),
                    false,
                    Some(anyhow!(e)),
                );
                error!(err = %cal_err, "Failed Blake2b init.");
                cal_err
            })?;

        let id = id_from_buffer(nonce)?;

        Ok(KeyHandle {
            implementation: SoftwareKeyHandle::new(id, spec, derived_key, None)
                .unwrap()
                .into(),
        })
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.key.clone())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key."]
    fn delete(self) -> Result<(), CalError> {
        if let Some(s) = &self.storage_manager {
            s.delete(self.key_id.clone())
        }
        Ok(())
    }

    fn spec(&self) -> KeySpec {
        self.spec
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
                        .inspect_err(|e| error!("Failed to verify signature: {e:?}"))
                        .is_ok(),
                )
            }
            _ => todo!(),
        }
    }

    fn encrypt_data(&self, _data: &[u8], _iv: &[u8]) -> Result<Vec<u8>, CalError> {
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
            self.signing_key
                .clone()
                .ok_or_else(|| CalError::missing_key(self.key_id.clone(), KeyType::Private))
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

    fn spec(&self) -> KeyPairSpec {
        self.spec
    }
}

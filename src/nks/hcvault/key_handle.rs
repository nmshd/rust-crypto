use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;
use super::NksProvider;
use base64::{engine::general_purpose, Engine};
use tracing::instrument;


//TODO use CAL once it can compile
use crate::common::{
    crypto::algorithms::encryption::AsymmetricEncryption, error::SecurityModuleError,
    traits::key_handle::KeyHandle,
};

use arrayref::array_ref;
use base64::prelude::BASE64_STANDARD;
//use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer as RSASigner, Verifier as RSAVerifier};
use openssl::pkey::{ Public, Private};
use serde_json::{json, Value};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use openssl::sign::{Signer, Verifier};

use x25519_dalek::{
    PublicKey as X25519PublicKey, PublicKey, StaticSecret as X25519StaticSecret, StaticSecret,
};
use crate::nks::NksConfig;
use crate::SecurityModuleError::InitializationError;

impl KeyHandle for NksProvider {
    #[tracing::instrument]
    fn sign_data(&self,
                 _data: &[u8],
    ) -> Result<Vec<u8>, SecurityModuleError> {

        // Determine the key algorithm based on the key or some other means
        let key_algorithm = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>().unwrap().key_algorithm;
        let data = _data;

        if (self.private_key.is_empty() || data.is_empty()) {
            return Err(InitializationError("Private key is empty".to_string()));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA signing method
                    let private_key_pem = self.private_key.as_bytes();
                    let rsa = Rsa::private_key_from_pem(private_key_pem)
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_rsa(rsa).map_err(|_| SecurityModuleError::KeyError)?;
                    let mut signer = RSASigner::new(MessageDigest::sha256(), &pkey)
                        .map_err(|_| SecurityModuleError::SigningFailed)?;
                    signer.update(data).map_err(|_| SecurityModuleError::SigningFailed)?;
                    signer.sign_to_vec().map_err(|_| SecurityModuleError::SigningFailed)
                }
                AsymmetricEncryption::Ecc(ecdsa) => {
                    // ECC signing method
                    let ec_key = openssl::ec::EcKey::private_key_from_pem(&self.private_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_ec_key(ec_key).map_err(|_| SecurityModuleError::KeyError)?;
                    let mut signer = RSASigner::new(MessageDigest::sha256(), &pkey)
                        .map_err(|_| SecurityModuleError::SigningFailed)?;
                    signer.update(data).map_err(|_| SecurityModuleError::SigningFailed)?;
                    signer.sign_to_vec().map_err(|_| SecurityModuleError::SigningFailed)
                }
                _ => Err(SecurityModuleError::UnsupportedAlgorithm),
            }
        }
    }


    #[tracing::instrument]
    fn decrypt_data(&self,
                    _encrypted_data: &[u8],
                    ) -> Result<Vec<u8>, SecurityModuleError> {
        // Determine the key algorithm based on the key or some other means
        let key_algorithm = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>().unwrap().key_algorithm;
        let encrypted_data = _encrypted_data;

        if self.private_key.is_empty() || encrypted_data.is_empty() {
            return Err(InitializationError("Private key or encrypted data is empty".to_string()));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA decryption method
                    let rsa = Rsa::private_key_from_pem(&self.private_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let mut decrypted_data = vec![0; rsa.size() as usize];
                    rsa.private_decrypt(encrypted_data, &mut decrypted_data, Padding::PKCS1)
                        .map_err(|_| SecurityModuleError::DecryptionError("RSA decryption failed".to_string()))?;
                    let last_non_zero_pos = decrypted_data.iter().rposition(|&x| x != 0).unwrap_or(0) + 1;
                    let (decrypted_data, _) = decrypted_data.split_at(last_non_zero_pos);

                    Ok(decrypted_data.to_vec())
                }
                AsymmetricEncryption::Ecc(ecdh) => {
                    // ECC decryption method
                    let ec_key = openssl::ec::EcKey::private_key_from_pem(&self.private_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_ec_key(ec_key).map_err(|_| SecurityModuleError::KeyError)?;
                    // Here you need to implement the decryption logic for ECC
                    // This will depend on the specific ECC scheme you are using
                    todo!();
                }
                _ => Err(SecurityModuleError::UnsupportedAlgorithm),
            }
        }
    }

    #[tracing::instrument]
    fn encrypt_data(&self,
                    _data: &[u8],
                    ) -> Result<Vec<u8>, SecurityModuleError> {
        // Determine the key algorithm based on the key or some other means
        let key_algorithm = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>().unwrap().key_algorithm;
        let data = _data;

        if self.private_key.is_empty() || data.is_empty() {
            return Err(InitializationError("Private key or data is empty".to_string()));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA encryption method
                    let rsa = Rsa::public_key_from_pem(&self.public_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let mut encrypted_data = vec![0; rsa.size() as usize];
                    rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
                        .map_err(|_| SecurityModuleError::EncryptionError("RSA encryption failed".to_string()))?;
                    Ok(encrypted_data)
                }
                AsymmetricEncryption::Ecc(ecdh) => {
                    // ECC encryption method
                    let ec_key = openssl::ec::EcKey::public_key_from_pem(&self.public_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_ec_key(ec_key).map_err(|_| SecurityModuleError::KeyError)?;
                    // Here you need to implement the encryption logic for ECC
                    // This will depend on the specific ECC scheme you are using
                    todo!();
                }
                _ => Err(SecurityModuleError::UnsupportedAlgorithm),
            }
        }
    }

    #[tracing::instrument]
    fn verify_signature(
        &self,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        // Determine the key algorithm based on the key or some other means
        let key_algorithm = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>().unwrap().key_algorithm;
        let data = _data;
        let signature = _signature;

        if self.public_key.is_empty() || data.is_empty() || signature.is_empty() {
            return Err(InitializationError("Public key, data or signature is empty".to_string()));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA signature verification method
                    let public_key_pem = self.public_key.as_bytes();
                    let rsa = Rsa::public_key_from_pem(public_key_pem)
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_rsa(rsa).map_err(|_| SecurityModuleError::KeyError)?;
                    let mut verifier = RSAVerifier::new(MessageDigest::sha256(), &pkey)
                        .map_err(|_| SecurityModuleError::VerificationFailed)?;
                    verifier.update(data).map_err(|_| SecurityModuleError::VerificationFailed)?;
                    Ok(verifier.verify(signature).map_err(|_| SecurityModuleError::VerificationFailed)?)
                }
                AsymmetricEncryption::Ecc(ecdsa) => {
                    // ECC signature verification method
                    let ec_key = openssl::ec::EcKey::public_key_from_pem(&self.public_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_ec_key(ec_key).map_err(|_| SecurityModuleError::KeyError)?;
                    let mut verifier = RSAVerifier::new(MessageDigest::sha256(), &pkey)
                        .map_err(|_| SecurityModuleError::VerificationFailed)?;
                    verifier.update(data).map_err(|_| SecurityModuleError::VerificationFailed)?;
                    Ok(verifier.verify(signature).map_err(|_| SecurityModuleError::VerificationFailed)?)
                }
                _ => Err(SecurityModuleError::UnsupportedAlgorithm),
            }
        }
    }
}

/// Adds a new signature to the secrets JSON object.
///
/// This function takes a mutable `Option<Value>` representing the secrets JSON object, a `Vec<u8>` representing the signature, a string slice representing the ID, and a string slice representing the hash algorithm. It converts the signature to a base64 string, creates a new signature object, and adds it to the signatures array in the secrets JSON object.
///
/// # Arguments
///
/// * `secrets_json` - A mutable `Option<Value>` representing the secrets JSON object. If `None`, the function will return an error.
/// * `signature` - A `Vec<u8>` representing the signature to be added to the secrets JSON object.
/// * `id` - A string slice representing the ID of the new signature.
/// * `hash_algorithm` - A string slice representing the hash algorithm used for the new signature.
///
/// # Returns
///
/// A `Result<Option<Value>, SecurityModuleError>` that, on success, contains the updated secrets JSON object. If the `secrets_json` is `None` or if the `signatures` array is not found, it returns a `SecurityModuleError::NksError`.
pub fn add_signature_to_secrets(mut secrets_json: Option<Value>, signature: Vec<u8>, id: &str, hash_algorithm: &str) -> Result<Option<Value>, SecurityModuleError> {
    // Convert the signature to a base64 string
    let signature_base64 = general_purpose::STANDARD.encode(&signature);

    // Create a new signature object
    let new_signature = json!({
        "id": id,
        "signature": signature_base64,
        "hashAlgorithm": hash_algorithm,
    });

    // Check if secrets_json is None
    if let Some(secrets_json) = &mut secrets_json {
        // Get the signatures array
        if let Some(signatures) = secrets_json["data"]["signatures"].as_array_mut() {
            // Add the new signature to the array
            signatures.push(new_signature);
            Ok(Some(secrets_json.clone()))
        } else {
            println!("Signatures array not found in secrets_json");
            Err(SecurityModuleError::NksError)
        }
    } else {
        println!("Secrets JSON is empty");
        Err(SecurityModuleError::NksError)
    }
}
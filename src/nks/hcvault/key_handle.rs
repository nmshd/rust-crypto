use super::NksProvider;
use base64::{decode, engine::general_purpose, Engine};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;
use tracing::instrument;

//TODO use CAL once it can compile
use crate::common::{
    crypto::algorithms::encryption::AsymmetricEncryption, error::SecurityModuleError,
    traits::key_handle::KeyHandle,
};

use arrayref::array_ref;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier, VerifyingKey};
//use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer as RSASigner, Verifier as RSAVerifier};
use serde_json::{json, Value};
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::{box_, scalarmult, secretbox};

use crate::nks::NksConfig;
use crate::SecurityModuleError::InitializationError;
use x25519_dalek::{
    PublicKey as X25519PublicKey, PublicKey, StaticSecret as X25519StaticSecret, StaticSecret,
};
use crate::common::crypto::algorithms::encryption::{EccCurves, EccSchemeAlgorithm};
use crate::common::crypto::algorithms::hashes::*;

impl KeyHandle for NksProvider {
    #[tracing::instrument]
    fn sign_data(&self, _data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        if let Some(nks_config) = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
            let key_algorithm = nks_config.key_algorithm;
            let data = _data;
            let hash = nks_config.hash;

            if (self.private_key.is_empty() || data.is_empty()) {
                return Err(InitializationError("Private key is empty".to_string()));
            } else {
                match key_algorithm {
                    AsymmetricEncryption::Rsa(key_bits) => {
                        // RSA signing method
                        let private_key_pem = self.private_key.as_bytes();
                        let rsa = Rsa::private_key_from_pem(private_key_pem)
                            .map_err(|_| SecurityModuleError::KeyError)?;
                        let pkey = PKey::from_rsa(rsa).map_err(|_| SecurityModuleError::KeyError)?;
                        // Create the signer based on the hash algorithm
                        let mut signer = match hash {
                            Hash::Sha1 => RSASigner::new(MessageDigest::sha1(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha224) => RSASigner::new(MessageDigest::sha224(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha256) => RSASigner::new(MessageDigest::sha256(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha384) => RSASigner::new(MessageDigest::sha384(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha512) => RSASigner::new(MessageDigest::sha512(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_224) => RSASigner::new(MessageDigest::sha3_224(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_256) => RSASigner::new(MessageDigest::sha3_256(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_384) => RSASigner::new(MessageDigest::sha3_384(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_512) => RSASigner::new(MessageDigest::sha3_512(), &pkey),
                            Hash::Md5 => RSASigner::new(MessageDigest::md5(), &pkey),
                            Hash::Ripemd160 => RSASigner::new(MessageDigest::ripemd160(), &pkey),
                            //Md2 and Md4 are not supported by openssl crate
                            _ => return Err(SecurityModuleError::UnsupportedAlgorithm),
                        }.map_err(|_| SecurityModuleError::SigningFailed)?;
                        signer
                            .update(data)
                            .map_err(|_| SecurityModuleError::SigningFailed)?;
                        signer
                            .sign_to_vec()
                            .map_err(|_| SecurityModuleError::SigningFailed)
                    }
                    AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Curve25519)) => {
                        // ECC signing method
                        let static_secret = decode_base64_private_key(self.private_key.as_str());
                        let signing_key = SigningKey::from_bytes(&static_secret.to_bytes());
                        let signature_sig = signing_key.sign(data);
                        Ok(signature_sig.to_vec())
                    }
                    _ => Err(SecurityModuleError::UnsupportedAlgorithm),
                }
            }
        } else {
            println!("Failed to downcast to NksConfig");
            Err(SecurityModuleError::NksError)
        }
    }

    #[tracing::instrument]
    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        // Determine the key algorithm based on the key or some other means
        let key_algorithm = self
            .config
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<NksConfig>()
            .unwrap()
            .key_algorithm;
        let encrypted_data = _encrypted_data;

        if self.private_key.is_empty() || encrypted_data.is_empty() {
            return Err(InitializationError(
                "Private key or encrypted data is empty".to_string(),
            ));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA decryption method
                    let rsa = Rsa::private_key_from_pem(&self.private_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let mut decrypted_data = vec![0; rsa.size() as usize];
                    rsa.private_decrypt(encrypted_data, &mut decrypted_data, Padding::PKCS1)
                        .map_err(|_| {
                            SecurityModuleError::DecryptionError(
                                "RSA decryption failed".to_string(),
                            )
                        })?;
                    let last_non_zero_pos =
                        decrypted_data.iter().rposition(|&x| x != 0).unwrap_or(0) + 1;

                    let (decrypted_data, _) = decrypted_data.split_at(last_non_zero_pos);

                    Ok(decrypted_data.to_vec())
                }
                AsymmetricEncryption::Ecc(ecdh) => {
                    let public_key_bytes = BASE64_STANDARD
                        .decode(self.public_key.as_bytes())
                        .expect("Invalid public key base64");
                    let private_key_bytes = BASE64_STANDARD
                        .decode(self.private_key.as_bytes())
                        .expect("Invalid private key base64");

                    let public_key =
                        box_::PublicKey::from_slice(&public_key_bytes).expect("Invalid public key");
                    let private_key = box_::SecretKey::from_slice(&private_key_bytes)
                        .expect("Invalid private key");

                    // Split the encrypted data into the nonce and the encrypted message
                    let (nonce_bytes, encrypted_message) =
                        _encrypted_data.split_at(box_::NONCEBYTES);
                    let nonce = box_::Nonce::from_slice(nonce_bytes).expect("Invalid nonce");

                    // Decrypt the message
                    let decrypted_message =
                        box_::open(encrypted_message, &nonce, &public_key, &private_key).map_err(
                            |_| {
                                SecurityModuleError::DecryptionError(
                                    "Decryption failed".to_string(),
                                )
                            },
                        )?;

                    Ok(decrypted_message)
                }
                _ => Err(SecurityModuleError::UnsupportedAlgorithm),
            }
        }
    }

    #[tracing::instrument]
    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let key_algorithm = self
            .config
            .as_ref()
            .unwrap()
            .as_any()
            .downcast_ref::<NksConfig>()
            .unwrap()
            .key_algorithm;
        let data = _data;

        if self.private_key.is_empty() || data.is_empty() {
            return Err(InitializationError(
                "Private key or data is empty".to_string(),
            ));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA encryption method
                    let rsa = Rsa::public_key_from_pem(&self.public_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let mut encrypted_data = vec![0; rsa.size() as usize];
                    rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
                        .map_err(|_| {
                            SecurityModuleError::EncryptionError(
                                "RSA encryption failed".to_string(),
                            )
                        })?;
                    Ok(encrypted_data)
                }
                AsymmetricEncryption::Ecc(ecdh) => {
                    let public_key_bytes = BASE64_STANDARD
                        .decode(self.public_key.as_bytes())
                        .expect("Invalid public key base64");
                    let private_key_bytes = BASE64_STANDARD
                        .decode(self.private_key.as_bytes())
                        .expect("Invalid private key base64");

                    let public_key =
                        box_::PublicKey::from_slice(&public_key_bytes).expect("Invalid public key");
                    let private_key = box_::SecretKey::from_slice(&private_key_bytes)
                        .expect("Invalid private key");

                    let nonce = box_::gen_nonce();
                    let encrypted_message = box_::seal(data, &nonce, &public_key, &private_key);

                    // Concatenate the nonce and the encrypted message into a single Vec<u8>
                    let mut result =
                        Vec::with_capacity(nonce.as_ref().len() + encrypted_message.len());
                    result.extend_from_slice(nonce.as_ref());
                    result.extend_from_slice(&encrypted_message);
                    Ok(result)
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
        if let Some(nks_config) = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
            let key_algorithm = nks_config.key_algorithm;
            let data = _data;
            let signature = _signature;
            let hash = nks_config.hash;

            if self.public_key.is_empty() || data.is_empty() || signature.is_empty() {
                return Err(InitializationError(
                    "Public key, data or signature is empty".to_string(),
                ));
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
                        let mut verifier = match hash {
                            Hash::Sha1 => RSAVerifier::new(MessageDigest::sha1(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha224) => RSAVerifier::new(MessageDigest::sha224(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha256) => RSAVerifier::new(MessageDigest::sha256(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha384) => RSAVerifier::new(MessageDigest::sha384(), &pkey),
                            Hash::Sha2(Sha2Bits::Sha512) => RSAVerifier::new(MessageDigest::sha512(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_224) => RSAVerifier::new(MessageDigest::sha3_224(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_256) => RSAVerifier::new(MessageDigest::sha3_256(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_384) => RSAVerifier::new(MessageDigest::sha3_384(), &pkey),
                            Hash::Sha3(Sha3Bits::Sha3_512) => RSAVerifier::new(MessageDigest::sha3_512(), &pkey),
                            Hash::Md5 => RSAVerifier::new(MessageDigest::md5(), &pkey),
                            Hash::Ripemd160 => RSAVerifier::new(MessageDigest::ripemd160(), &pkey),
                            //Md2 and Md4 are not supported by openssl crate
                            _ => return Err(SecurityModuleError::UnsupportedAlgorithm),
                        }.map_err(|_| SecurityModuleError::SigningFailed)?;
                        verifier
                            .update(data)
                            .map_err(|_| SecurityModuleError::VerificationFailed)?;
                        Ok(verifier
                            .verify(signature)
                            .map_err(|_| SecurityModuleError::VerificationFailed)?)
                    }
                    AsymmetricEncryption::Ecc(ecdsa) => {
                        // ECC signature verification method
                        let signature_sig = Signature::from_slice(signature)
                            .map_err(|_| SecurityModuleError::InvalidSignature)?;
                        let public_key_bytes = BASE64_STANDARD
                            .decode(&self.public_key)
                            .map_err(|_| SecurityModuleError::InvalidPublicKey)?;
                        let verifying_result = VerifyingKey::from_bytes(
                            <&[u8; 32]>::try_from(public_key_bytes.as_slice())
                                .map_err(|_| SecurityModuleError::InvalidPublicKey)?,
                        );
                        match verifying_result {
                            Ok(verifying_key) => Ok(verifying_key.verify(data, &signature_sig).is_ok()),
                            Err(_) => Err(SecurityModuleError::VerificationFailed),
                        }
                    }
                    _ => Err(SecurityModuleError::UnsupportedAlgorithm),
                }
            }
        } else {
            println!("Failed to downcast to NksConfig");
            Err(SecurityModuleError::NksError)
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
pub fn add_signature_to_secrets(
    mut secrets_json: Option<Value>,
    signature: Vec<u8>,
    id: &str,
    hash_algorithm: &str,
) -> Result<Option<Value>, SecurityModuleError> {
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

pub fn decode_base64_private_key(private_key_base64: &str) -> StaticSecret {
    let private_key_base64 = private_key_base64; // example private key
    let private_key_bytes = BASE64_STANDARD
        .decode(private_key_base64.as_bytes())
        .expect("Invalid private key base64");
    let x25519_private_key = X25519StaticSecret::from(*array_ref![private_key_bytes, 0, 32]);
    return x25519_private_key;
}

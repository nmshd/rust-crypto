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
use reqwest::Url;
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
    /// Signs the given data using the configured key and algorithm.
    ///
    /// # Arguments
    ///
    /// * `_data` - A slice of bytes representing the data to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
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

    /// Decrypts the given encrypted data using the configured key and algorithm.
    ///
    /// # Arguments
    ///
    /// * `_encrypted_data` - A slice of bytes representing the encrypted data.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
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

    /// Encrypts the given data using the configured key and algorithm.
    ///
    /// # Arguments
    ///
    /// * `_data` - A slice of bytes representing the data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
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

    /// Verifies the given signature against the provided data using the configured key and algorithm.
    ///
    /// # Arguments
    ///
    /// * `_data` - A slice of bytes representing the data that was signed.
    /// * `_signature` - A slice of bytes representing the signature to be verified.
    ///
    /// # Returns
    ///
    /// A `Result` containing `true` if the signature is valid, `false` if it is invalid, or a `SecurityModuleError` on failure.
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

/// Decodes a base64-encoded private key.
///
/// # Arguments
///
/// * `private_key_base64` - A string slice representing the base64-encoded private key.
///
/// # Returns
///
/// A `StaticSecret` representing the decoded private key.
pub fn decode_base64_private_key(private_key_base64: &str) -> StaticSecret {
    let private_key_base64 = private_key_base64; // example private key
    let private_key_bytes = BASE64_STANDARD
        .decode(private_key_base64.as_bytes())
        .expect("Invalid private key base64");
    let x25519_private_key = X25519StaticSecret::from(*array_ref![private_key_bytes, 0, 32]);
    return x25519_private_key;
}

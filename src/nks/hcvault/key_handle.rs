use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;
use super::NksProvider;
use base64::Engine;
use tracing::instrument;


//TODO use CAL once it can compile
use crate::common::{
    crypto::algorithms::encryption::AsymmetricEncryption, error::SecurityModuleError,
    traits::key_handle::KeyHandle,
};

use arrayref::array_ref;
use base64::prelude::BASE64_STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer as RSASigner, Verifier as RSAVerifier};
use openssl::pkey::{ Public, Private};
use serde_json::{json, Value};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

use x25519_dalek::{
    PublicKey as X25519PublicKey, PublicKey, StaticSecret as X25519StaticSecret, StaticSecret,
};
use crate::SecurityModuleError::InitializationError;

impl KeyHandle for NksProvider {
    #[tracing::instrument]
    fn sign_data(&self,
                 _data: &[u8],
    ) -> Result<Vec<u8>, SecurityModuleError> {

        // Determine the key algorithm based on the key or some other means
        let key_algorithm = "rsa";
        ///todo: use the key algorithm from the config
        let data = _data;

        if (self.private_key.is_empty() || data.is_empty()) {
            return Err(InitializationError("Private key is empty".to_string()));
        } else {
            match key_algorithm {
                "rsa" => {
                    // RSA signing method
                    let rsa = Rsa::private_key_from_pem(&self.private_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_rsa(rsa).map_err(|_| SecurityModuleError::KeyError)?;
                    let mut signer = RSASigner::new(MessageDigest::sha256(), &pkey)
                        .map_err(|_| SecurityModuleError::SigningFailed)?;
                    signer.update(data).map_err(|_| SecurityModuleError::SigningFailed)?;
                    signer.sign_to_vec().map_err(|_| SecurityModuleError::SigningFailed)
                }
                "ecc" => {
                    todo!();
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
        let key_algorithm = "rsa";
        let encrypted_data = _encrypted_data;

        if self.private_key.is_empty() || encrypted_data.is_empty() {
            return Err(InitializationError("Private key or encrypted data is empty".to_string()));
        } else {
            match key_algorithm {
                "rsa" => {
                    // RSA decryption method
                    let rsa = Rsa::private_key_from_pem(&self.private_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let mut decrypted_data = vec![0; rsa.size() as usize];
                    rsa.private_decrypt(encrypted_data, &mut decrypted_data, Padding::PKCS1)
                        .map_err(|_| SecurityModuleError::DecryptionError("RSA decryption failed".to_string()))?;
                    Ok(decrypted_data)
                }
                "ecc" => {
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
        let key_algorithm = "rsa";
        let data = _data;

        if self.private_key.is_empty() || data.is_empty() {
            return Err(InitializationError("Private key or data is empty".to_string()));
        } else {
            match key_algorithm {
                "rsa" => {
                    // RSA encryption method
                    let rsa = Rsa::public_key_from_pem(&self.public_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let mut encrypted_data = vec![0; rsa.size() as usize];
                    rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
                        .map_err(|_| SecurityModuleError::EncryptionError("RSA encryption failed".to_string()))?;
                    Ok(encrypted_data)
                }
                "ecc" => {
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
        let key_algorithm = "rsa";
        ///todo: use the key algorithm from the config
        let data = _data;
        let signature = _signature;

        if self.public_key.is_empty() || data.is_empty() || signature.is_empty() {
            return Err(InitializationError("Public key, data or signature is empty".to_string()));
        } else {
            match key_algorithm {
                "rsa" => {
                    // RSA signature verification method
                    let rsa = Rsa::public_key_from_pem(&self.public_key.as_bytes())
                        .map_err(|_| SecurityModuleError::KeyError)?;
                    let pkey = PKey::from_rsa(rsa).map_err(|_| SecurityModuleError::KeyError)?;
                    let mut verifier = RSAVerifier::new(MessageDigest::sha256(), &pkey)
                        .map_err(|_| SecurityModuleError::VerificationFailed)?;
                    verifier.update(data).map_err(|_| SecurityModuleError::VerificationFailed)?;
                    Ok(verifier.verify(signature).map_err(|_| SecurityModuleError::VerificationFailed)?)
                }
                "ecc" => {
                todo!();
                }
                _ => Err(SecurityModuleError::UnsupportedAlgorithm),
            }
        }
    }
}

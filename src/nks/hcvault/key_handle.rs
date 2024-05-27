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
        let private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDpccmrGEsNL7+P6/lLpZBLDLWnwg9qOOxaRK2qscW4knCij5teinwiiaLKB7OtmUwvzN5mJ1wYYdFE6y3nOIXmN8y7xbAKzvBAN7TEXBss/KagtlCXlVTZ0moVZzRNZ8g8BKe1mXgKa2mAjL4PeAQZZfKqtd0AIeqvc6afig/D0tNVxdJdjGyYL+0ul8URu4LtqC9p8i9SbHGWcO1ELJGHJl4OSmvI0P+FqcDRv1QyiZ2ZNzcHcb+zUMAwfHUR130bRzEzgcZUcdKEEvzVfhL6juhQoAuRVriwOi4cIP+x4yjxV0/Tnil1DXwfe7fwfwhabUykI3M4wqTzBf2hKBJfAgMBAAECggEAUS22mX7bKny+OsguavXqFY8X5HyBa8jbuBBF7CPhw+t4q68QsnGp9UCzkVnYS7gRXFX7yL5LMldhtHur/MoVFhe1ZF68dyW7Ojmk7Nuyv5QkRaLgp7XQSeb36PV4pKpAYU6lG2uA6O6tQ3yt4yczFbn0BxUzAwbIW7b17GjQTqHpubS8eratu+fDrUH12uDe8TiMWhb3v831tBkNv7lPdzq20WW0mf66JnJy7uYnEumPP14rjunaclB9tPyHJRBFsELsPsHWTVoTB1ozp344NPlTlNuR1cPb5Qt3GLr+hF0F3EXyZfADjQSKuyl+zm8ZMxoX1nKGJnIfu5cHnQyUIQKBgQD5USFejyNlPSK9bXg8ujAcBt5OnGLE8TrExLD2sWqtQY5m1eIJZG7gR4b8jW6J6f8o9SNkV/DiX8KchGjf9c8jSEhyGdWi501nEWN3nisqb/Y0xtilMzPV7+BNRAJ95oKKDoILCr6Bv7cHh4q++JARaHF8OkYipA3Lg4yg5cfKSQKBgQDvs7y2q9g1OYPyTGTZoxEqn81AucC67x1wUVkjVtnk/BU2jPyArf1LBAgyRIcuPr0R2PgLbCgtDmq10b/T6BNIircTA61ic9r5X0LdD8M94FT7iiXckZv7NOlvNYJgdk3KqGD0ZxMV5HhnhYoC4HUiuq4pPO2vjmPygr3HttA3ZwKBgFcgwi+giDceGWDnu8hFLQDuaYxBXMcEoowXTNy5fdVUfqZzgo3TumfIt2TVLFcoHlK68IZlsTn7SzCVmW0DI0NqRF8TpjRK7yLg0ckAzocDH6CsCRQag7f1H4cBCHnlL6N9lHa1Z4RCcn1AIf3BMd/Thy1p1A7RFD0WGPQ1uQ95AoGBALrgcCIie5+TRbFjqcSbg0it6YGqz/1tapAke9A3aA1EEu3CoSFZhH41mIZIMvP06ca+VzPgkLn/4WX7LwjwiAgoTW6/kS+Oj4uXnzNllJvrB5ZMMBR0WR1SNSQEna7CzQdQmrYwngqVYuGilOSFRg1baWixHcWex4FMONU5S7/FAoGAakVdaKe24kGoICHZjfz7RX3gk2e+0UfoN4x1vfCN9mnq0P5KZSPPuQS/mS1mhoLFgnYE+iPl5CNaWQPNTTOCrYHSbyUpmYCG4e+ZZy5nlV66i+pXug6CF1DHoqsjsU7+SX0RQ4YxyZmeTaYOktrHOfb7kaLS+1DSlCVWsdXaer4=";
        let priv_key = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQ0KTUlJQ1d3SUJBQUtCZ1FDaG9XdTJOVnVlSXprZXdxOTNKUVZJQXIxOXRZc3l2YmxzbHIvWGsxd0tRMUpNaWZscQ0KZ1hBM2VjNkMrc2E5YlJ2K0V4WW9NNDZ4V00wY2NQNkI2NHVwQ0xPQU0wc3N0M2pHejJqNmhjRGdJQmNIclBnVw0KTTkxall0TXlzWjNna3QvcUJ3UFNxYzZZNWp4VHgrdm5KQWZtcHhxMVRwV0xuNFBsSE9rdkhkNW8yd0lEQVFBQg0KQW9HQVJ2VFpsNFUzTW1aZU5pM2I0QjlsZ1NhS3o3dzZYczFCc1BWQlJUK1JBWVJxaGVWd2xKdzhpbTQwQmZaWA0KOTJNR0RmV05IWnI4d3Npc1N4Y2o5QjlYRU94K01tMnFWK0FmWTk0MCsvRDQyQW1GU3JoQUljNG1Ca1BhSG56NA0KVERTa2NDbmp3RmZ0ZkVzU0tWc24ycmUrQk54ekJSTGhYVy9lNFlJUC9EeGFuTmtDUVFETi9ZbEFIbUJiVnVuRA0KbXd2dkkvTUcwc3RNSlU4V2w2bjNMLzJnRkR1RTVjc1dFYTFhTk5yKzNhVDgvdE1rQjYvWFlNOTBkSjRWcTVGYg0KVUdUOUtpOEhBa0VBeU43aTlTbEhZSjFMWkZTWE9JTGgwQitRMEdDQzJQbFhhNi8vMXoycUdhZDRjUldsWmZpaw0KOEx3NDJVL2hocTVXOGtBNVdiRno2NnBIQmgrcEZrYnVqUUpBRlhsSXhaWmxGU0NLWGduYnhLSkt3M3RXRmlvTg0KaEoxcTZvbm1Ocm5sT29WNkZtTGhYM1lESG02Y3RJTWNIN1Z0YjFaNFNmdWVQMFFUY3lGK1phWHdJUUpBZW1LaQ0Kc1hDM0ZueC94Tjl0UzNjakVtVkpIRXpSTEZXdkYrT2g0NGlrclFER2QxQVMrREFvZnF5UGpvZ0hCc0lPSTRkUg0KNmY0ZWZNWEFoRkNoK3ZxNHVRSkFLdVBiVDNpZVNLTlR4Z1J0eDJXY3VPanB2MXZuQ29mMk9OVkxsOGMvSVJDRA0KdCtrbW5qU0wzQmZLdkJ1RHJ0RUJSRENQY1FyUnRVTjFLR0FWQXpWWndnPT0NCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t";

        if (self.private_key.is_empty() || data.is_empty()) {
            return Err(InitializationError("Private key is empty".to_string()));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA signing method
                    //println!("{}", &self.private_key);
                    let private_key_bytes = BASE64_STANDARD.decode(priv_key.as_bytes()).expect("Invalid private key base64");
                    let rsa = Rsa::private_key_from_pem(private_key_bytes.as_slice())
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
                    Ok(decrypted_data)
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
        let pub_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRQ2hvV3UyTlZ1ZUl6a2V3cTkzSlFWSUFyMTkNCnRZc3l2YmxzbHIvWGsxd0tRMUpNaWZscWdYQTNlYzZDK3NhOWJSditFeFlvTTQ2eFdNMGNjUDZCNjR1cENMT0ENCk0wc3N0M2pHejJqNmhjRGdJQmNIclBnV005MWpZdE15c1ozZ2t0L3FCd1BTcWM2WTVqeFR4K3ZuSkFmbXB4cTENClRwV0xuNFBsSE9rdkhkNW8yd0lEQVFBQg0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t";

        if self.public_key.is_empty() || data.is_empty() || signature.is_empty() {
            return Err(InitializationError("Public key, data or signature is empty".to_string()));
        } else {
            match key_algorithm {
                AsymmetricEncryption::Rsa(rsa) => {
                    // RSA signature verification method
                    let public_key_bytes = BASE64_STANDARD.decode(pub_key.as_bytes()).expect("Invalid private key base64");
                    let rsa = Rsa::public_key_from_pem(public_key_bytes.as_slice())
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
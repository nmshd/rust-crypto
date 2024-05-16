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
    fn sign_data(&self, _data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }
    #[tracing::instrument]
    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }
    #[tracing::instrument]
    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }
    #[tracing::instrument]
    fn verify_signature(
        &self,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        todo!()
    }
//impl NksProvider {
//     /// Signs the given data using the cryptographic key managed by the nks provider.
//     ///
//     /// # Arguments
//     ///
//     /// * `data` - A byte slice representing the data to be signed.
//     ///
//     /// # Returns
//     ///
//     /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
//
//     //TODO implement sign_data
//     #[instrument]
//     //fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
//     pub fn sign_data(data: &[u8], private_key: &str) -> Vec<u8> {
//         //TODO add error to result
//         //TODO add matching instead of if else
//         //TODO get key and algo from self not hardcoded or parameter
//         let key_algorithm = "rsa"; //either ecc or rsa
//
//         let mut signature: Vec<u8> = vec![];
//         if ("rsa".eq(key_algorithm)) {
//             //TODO ad support for encoded string, currently only works with decoded pem string
//             //let private_key_bytes = BASE64_STANDARD.decode(private_key.as_bytes()).expect("Invalid private key base64");
//             //let rsa = Rsa::private_key_from_pem(&private_key_bytes.as_slice()).expect("failed to create RSA object");
//             let rsa = Rsa::private_key_from_pem(private_key.as_bytes())
//                 .expect("failed to create RSA object");
//             let pkey = PKey::from_rsa(rsa).expect("failed to create PKey");
//             let mut signer =
//                 RSASigner::new(MessageDigest::sha256(), &*pkey).expect("failed to create signer");
//             signer.update(data).expect("failed to update signer");
//             signature = signer.sign_to_vec().expect("failed to sign data");
//         } else if ("ecc".eq(key_algorithm)) {
//             let static_secret = decode_base64_private_key(private_key);
//             let signing_key = SigningKey::from_bytes(&static_secret.to_bytes());
//             let signature_sig = signing_key.sign(data);
//             signature = signature_sig.to_vec();
//         } else {
//             todo!()
//         }
//         return signature;
//     }
//
//     /// Decrypts the given encrypted data using the cryptographic key managed by the nks provider.
//     ///
//     /// # Arguments
//     ///
//     /// * `encrypted_data` - A byte slice representing the data to be decrypted.
//     ///
//     /// # Returns
//     ///
//     /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
//
//     //TODO implement decrypt_data
//     /*
//     #[instrument]
//     fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
//     }
//
//      */
//
//     /// Encrypts the given data using the cryptographic key managed by the nks provider.
//     ///
//     /// # Arguments
//     ///
//     /// * `data` - A byte slice representing the data to be encrypted.
//     ///
//     /// # Returns
//     ///
//     /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
//
//     //TODO implement encrypt_data
//     #[instrument]
//     pub(crate) fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
//         match &self.key_algorithm {
//             AsymmetricEncryption::Rsa(_) => {
//                 let rsa = Rsa::public_key_from_pem(&self.public_key.as_bytes())
//                     .map_err(|_| SecurityModuleError::KeyError)?;
//                 Ok(rsa_encrypt(data, &rsa))
//             }
//             AsymmetricEncryption::Ecc(_) => {
//                 let public_key = box_::PublicKey::from_slice(&self.public_key.as_bytes())
//                     .ok_or(SecurityModuleError::KeyError)?;
//                 let private_key = box_::SecretKey::from_slice(&self.priv_key.as_bytes())
//                     .ok_or(SecurityModuleError::KeyError)?;
//                 encrypt_curve25519(data, &public_key, &private_key)
//                     .map_err(|_| SecurityModuleError::EncryptionError)
//             }
//             _ => Err(SecurityModuleError::UnsupportedAlgorithm),
//         }
//     }
//
//     /// Verifies the signature of the given data using the cryptographic key managed by the nks provider.
//     ///
//     /// # Arguments
//     ///
//     /// * `data` - A byte slice representing the data whose signature is to be verified.
//     /// * `signature` - A byte slice representing the signature to be verified against the data.
//     ///
//     /// # Returns
//     ///
//     /// A `Result` containing a boolean indicating whether the signature is valid (`true`) or not (`false`),
//     /// or a `SecurityModuleError` on failure.
//
//     #[instrument]
//     pub fn verify_signature(&self, data: &[u8], signature: &[u8], public_key: &str) -> Result<bool, SecurityModuleError> {
//         // Determine the key algorithm based on the public key or some other means
//         let key_algorithm = self.determine_key_algorithm(public_key)?;
//
//         match key_algorithm {
//             "ecc" => {
//                 let signature_sig = Signature::from_slice(signature).map_err(|_| SecurityModuleError::InvalidSignature)?;
//                 let public_key_bytes = BASE64_STANDARD.decode(public_key.as_bytes()).map_err(|_| SecurityModuleError::InvalidPublicKey)?;
//                 let verifying_result = VerifyingKey::from_bytes(<&[u8; 32]>::try_from(public_key_bytes.as_slice()).map_err(|_| SecurityModuleError::InvalidPublicKey)?);
//                 match verifying_result {
//                     Ok(verifying_key) => Ok(verifying_key.verify(data, &signature_sig).is_ok()),
//                     Err(_) => Err(SecurityModuleError::VerificationFailed),
//                 }
//             }
//             "rsa" => {
//                 let rsa = Rsa::public_key_from_pem(public_key.as_bytes()).map_err(|_| SecurityModuleError::InvalidPublicKey)?;
//                 let pkey = PKey::from_rsa(rsa).map_err(|_| SecurityModuleError::KeyError)?;
//                 let mut verifier = RSAVerifier::new(MessageDigest::sha256(), &*pkey).map_err(|_| SecurityModuleError::VerificationFailed)?;
//                 verifier.update(data).map_err(|_| SecurityModuleError::VerificationFailed)?;
//                 verifier.verify(signature).map_err(|_| SecurityModuleError::VerificationFailed)
//             }
//             _ => Err(SecurityModuleError::UnsupportedAlgorithm),
//         }
//     }
//
//
//
//     pub(crate) async fn get_token(
//         &self,
//         benchmark: bool,
//     ) -> anyhow::Result<String, Box<dyn std::error::Error>> {
//         let response: Value = reqwest::Client::new()
//             .get(self.nks_address.clone())
//             .header("accept", "*/*")
//             .send()
//             .await?
//             .json()
//             .await?;
//
//         if let Some(user_token) = response.get("token") {
//             if let Some(user_token_str) = user_token.as_str() {
//                 println!("{}", user_token_str);
//                 if !benchmark {
//                     let token_data = json!({
//                         "usertoken": user_token_str
//                     });
//                     fs::write("token.json", token_data.to_string())?;
//                 }
//                 return Ok(user_token_str.to_string());
//             }
//         }
//         println!("The response does not contain a 'token' field");
//         Ok(String::new())
//     }
//     pub(crate) async fn get_secrets(
//         &self,
//         token: &str,
//     ) -> anyhow::Result<String, Box<dyn std::error::Error>> {
//         let client = reqwest::Client::new();
//         let body = json!({
//             "token": token
//         });
//
//         let response: Value = client
//             .post(self.nks_address.clone())
//             .header("accept", "*/*")
//             .header("Content-Type", "application/json-patch+json")
//             .json(&body)
//             .send()
//             .await?
//             .json()
//             .await?;
//
//         let response_text = response.to_string();
//
//         if let Some(user_token) = response.get("newToken") {
//             if let Some(user_token_str) = user_token.as_str() {
//                 let token_data = json!({
//                     "usertoken": user_token_str
//                 });
//                 fs::write("token.json", token_data.to_string())?;
//             }
//         }
//
//         if response_text.is_empty() {
//             println!("Received empty response from server");
//             Ok(String::new())
//         } else {
//             let response: Value = serde_json::from_str(&response_text)?;
//             let pretty_response = serde_json::to_string_pretty(&response)
//                 .unwrap_or_else(|_| String::from("Error formatting JSON"));
//             Ok(pretty_response)
//         }
//     }
//
//     pub(crate) async fn add_secrets(
//         &self,
//         token: &str,
//         data: Value,
//     ) -> anyhow::Result<String, Box<dyn std::error::Error>> {
//         let client = reqwest::Client::new();
//         let body = json!({
//             "token": token,
//             "data": data
//         });
//
//         let response: Value = client
//             .post(self.nks_address.clone())
//             .header("accept", "*/*")
//             .header("Content-Type", "application/json-patch+json")
//             .json(&body)
//             .send()
//             .await?
//             .json()
//             .await?;
//
//         //save new token
//         if let Some(user_token) = response.get("newToken") {
//             if let Some(user_token_str) = user_token.as_str() {
//                 let token_data = json!({
//                     "usertoken": user_token_str
//                 });
//                 fs::write("token.json", token_data.to_string())?;
//             }
//         }
//
//         let pretty_response = serde_json::to_string_pretty(&response)
//             .unwrap_or_else(|_| String::from("Error formatting JSON"));
//         println!("{}", pretty_response);
//
//         Ok((pretty_response))
//     }
//
//     // pub(crate) async fn delete_secrets(&self, token: &str) -> anyhow::Result<(), dyn Error> {
//     //     let client = reqwest::Client::new();
//     //     let body = json!({
//     //         "token": token
//     //     });
//     //
//     //     let response: Value = client
//     //         .delete(self.nks_address.clone())
//     //         .header("accept", "*/*")
//     //         .header("Content-Type", "application/json-patch+json")
//     //         .json(&body)
//     //         .send()
//     //         .await?
//     //         .json()
//     //         .await?;
//     //
//     //     //save new token
//     //     if let Some(user_token) = response.get("newToken") {
//     //         if let Some(user_token_str) = user_token.as_str() {
//     //             let token_data = json!({
//     //                 "usertoken": user_token_str
//     //             });
//     //             fs::write("token.json", token_data.to_string());
//     //         }
//     //     }
//     //
//     //     let pretty_response = serde_json::to_string_pretty(&response)
//     //         .unwrap_or_else(|_| String::from("Error formatting JSON"));
//     //     println!("{}", pretty_response);
//     //
//     //     Ok(())
//     // }
//
//     pub(crate) fn get_usertoken_from_file() -> Option<String> {
//         let mut file = File::open("token.json").ok()?;
//         let mut contents = String::new();
//         file.read_to_string(&mut contents).ok()?;
//
//         let json: Value = serde_json::from_str(&contents).ok()?;
//
//         if let Some(usertoken) = json["usertoken"].as_str() {
//             return Some(usertoken.to_string());
//         } else {
//             println!("usertoken not found or invalid format.");
//             return None;
//         }
//     }
//
//     pub(crate) async fn get_and_save_key_pair(
//         &self,
//         token: &str,
//         key_name: &str,
//         key_type: &str,
//     ) -> std::result::Result<String, Box<dyn std::error::Error>> {
//         let client = reqwest::Client::new();
//         let request_body = json!(
//             {
//             "token": token,
//             "name": key_name,
//             "type": key_type
//             }
//         );
//         println!("body: {}", request_body);
//
//         let response = client
//             .post(self.nks_address.clone())
//             .header("accept", "*/*")
//             .header("Content-Type", "application/json-patch+json")
//             .json(&request_body)
//             .send()
//             .await?;
//
//         let status = response.status(); // Clone the status here
//         let response_text = response.text().await?;
//         if !status.is_success() {
//             println!("Error response:\n{}", response_text);
//             return Err(format!("Server returned status code: {}", status).into());
//         }
//
//         println!("Success response:\n{}", response_text);
//         let response_json: Value = serde_json::from_str(&response_text)?;
//
//         if let Some(user_token) = response_json.get("newToken") {
//             if let Some(user_token_str) = user_token.as_str() {
//                 let token_data = json!({
//                     "usertoken": user_token_str
//                 });
//                 fs::write("token.json", token_data.to_string())?;
//             }
//         }
//         let pretty_response = serde_json::to_string_pretty(&response_json)
//             .unwrap_or_else(|_| String::from("Error formatting JSON"));
//
//         Ok(pretty_response)
//     }
}

fn rsa_encrypt(data: &[u8], rsa: &Rsa<Public>) -> Vec<u8> {
    let mut encrypted_data = vec![0; rsa.size() as usize];
    rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
        .expect("failed to encrypt data");
    encrypted_data
}

fn rsa_decrypt(encrypted_data: &[u8], rsa: &Rsa<Private>) -> Vec<u8> {
    let mut decrypted_data = vec![0; rsa.size() as usize];
    rsa.private_decrypt(encrypted_data, &mut decrypted_data, Padding::PKCS1)
        .expect("failed to decrypt data");
    decrypted_data
}

fn rsa_sign(data: &[u8], pkey: &PKey<Private>) -> Vec<u8> {
    let mut signer =
        Signer::new(MessageDigest::sha256(), pkey).expect("failed to create signer");
    signer.update(data).expect("failed to update signer");
    signer.sign_to_vec().expect("failed to sign data")
}

fn rsa_verify_signature(data: &[u8], signature: &[u8], pkey: &PKey<Public>) -> bool {
    let mut verifier =
        Verifier::new(MessageDigest::sha256(), pkey).expect("failed to create verifier");
    verifier.update(data).expect("failed to update verifier");
    verifier
        .verify(signature)
        .expect("failed to verify signature")
}

fn encrypt_curve25519(message: &[u8], public_key: &box_::PublicKey, private_key: &box_::SecretKey) -> Result<(Vec<u8>, box_::Nonce), ()> {
    let nonce = box_::gen_nonce();
    let encrypted_message = box_::seal(message, &nonce, public_key, private_key);
    Ok((encrypted_message, nonce))
}
fn decrypt_cruve25519(encrypted_message: &[u8], nonce: &box_::Nonce, public_key: &box_::PublicKey, private_key: &box_::SecretKey) -> Result<Vec<u8>, ()> {
    let decrypted_message = box_::open(encrypted_message, nonce, public_key, private_key).map_err(|_| ())?;
    Ok(decrypted_message)
}

pub fn decode_base64_private_key(private_key_base64: &str) -> StaticSecret {
    //TODO find decoding solution without x25529 Static Secret
    let private_key_base64 = private_key_base64; // example private key
    let private_key_bytes = BASE64_STANDARD
        .decode(private_key_base64.as_bytes())
        .expect("Invalid private key base64");
    let x25519_private_key = X25519StaticSecret::from(*array_ref![private_key_bytes, 0, 32]);
    return x25519_private_key;
}
fn decode_base64(_public_key_base64: &str, _private_key_base64: &str ) -> (box_::PublicKey, box_::SecretKey) {
    let public_key_base64 = _public_key_base64;
    let private_key_base64 = _private_key_base64;

    let public_key_bytes = BASE64_STANDARD.decode(public_key_base64.as_bytes()).expect("Invalid public key base64");
    let private_key_bytes = BASE64_STANDARD.decode(private_key_base64.as_bytes()).expect("Invalid private key base64");

    let public_key = box_::PublicKey::from_slice(&public_key_bytes).unwrap();
    let private_key = box_::SecretKey::from_slice(&private_key_bytes).unwrap();

    return(public_key, private_key);
}
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
use openssl::rsa::Rsa;
use openssl::sign::{Signer as RSASigner, Verifier as RSAVerifier};
use x25519_dalek::{
    PublicKey as X25519PublicKey, PublicKey, StaticSecret as X25519StaticSecret, StaticSecret,
};

//impl KeyHandle for NksProvider {
impl NksProvider {
    /// Signs the given data using the cryptographic key managed by the nks provider.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.

    //TODO implement sign_data
    #[instrument]
    //fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
    pub fn sign_data(data: &[u8], private_key: &str) -> Vec<u8> {
        //TODO add error to result
        //TODO add matching instead of if else
        //TODO get key and algo from self not hardcoded or parameter
        let key_algorithm = "rsa"; //either ecc or rsa

        let mut signature: Vec<u8> = vec![];
        if ("rsa".eq(key_algorithm)) {
            //TODO ad support for encoded string, currently only works with decoded pem string
            //let private_key_bytes = BASE64_STANDARD.decode(private_key.as_bytes()).expect("Invalid private key base64");
            //let rsa = Rsa::private_key_from_pem(&private_key_bytes.as_slice()).expect("failed to create RSA object");
            let rsa = Rsa::private_key_from_pem(private_key.as_bytes())
                .expect("failed to create RSA object");
            let pkey = PKey::from_rsa(rsa).expect("failed to create PKey");
            let mut signer =
                RSASigner::new(MessageDigest::sha256(), &*pkey).expect("failed to create signer");
            signer.update(data).expect("failed to update signer");
            signature = signer.sign_to_vec().expect("failed to sign data");
        } else if ("ecc".eq(key_algorithm)) {
            let static_secret = decode_base64_private_key(private_key);
            let signing_key = SigningKey::from_bytes(&static_secret.to_bytes());
            let signature_sig = signing_key.sign(data);
            signature = signature_sig.to_vec();
        } else {
            todo!()
        }
        return signature;
    }

    /// Decrypts the given encrypted data using the cryptographic key managed by the nks provider.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.

    //TODO implement decrypt_data
    /*
    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
    }

     */

    /// Encrypts the given data using the cryptographic key managed by the nks provider.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.

    //TODO implement encrypt_data
    #[instrument]
    pub(crate) fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {}

    /// Verifies the signature of the given data using the cryptographic key managed by the nks provider.
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
    //fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
    pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &str) -> bool {
        //TODO add error to result
        //TODO get key and algo from self not hardcoded or parameter
        let key_algorithm = "rsa"; //either ecc or rsa

        let verification_result = match key_algorithm {
            "ecc" => {
                let signature_sig =
                    Signature::from_slice(signature).expect("Invalid signature byte slice");
                let public_key_bytes = BASE64_STANDARD
                    .decode(public_key.as_bytes())
                    .expect("Invalid public key base64");
                let verifying_result = VerifyingKey::from_bytes(
                    <&[u8; 32]>::try_from(public_key_bytes.as_slice()).unwrap(),
                );
                match verifying_result {
                    Ok(verifying_key) => verifying_key.verify(data, &signature_sig).is_ok(),
                    Err(err) => {
                        println!("{}", err);
                        false
                    }
                }
            }
            "rsa" => {
                //TODO ad support for encoded string, currently only works with decoded pem string
                //let public_key_bytes = BASE64_STANDARD.decode(public_key.as_bytes()).expect("Invalid public key base64");
                // let rsa = Rsa::public_key_from_pem(&public_key_bytes.as_slice()).expect("failed to create RSA object");
                let rsa = Rsa::public_key_from_pem(public_key.as_bytes())
                    .expect("failed to create RSA object");
                let pkey = PKey::from_rsa(rsa).expect("failed to create PKey");
                let mut verifier = RSAVerifier::new(MessageDigest::sha256(), &*pkey)
                    .expect("failed to create verifier");
                verifier.update(data).expect("failed to update verifier");
                verifier
                    .verify(signature)
                    .expect("failed to verify signature")
            }
            _ => false,
        };
        return verification_result;
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

    pub(crate) async fn get_token(
        &self,
        benchmark: bool,
    ) -> anyhow::Result<String, Box<dyn std::error::Error>> {
        let response: Value = reqwest::Client::new()
            .get(self.nks_address)
            .header("accept", "*/*")
            .send()
            .await?
            .json()
            .await?;

        if let Some(user_token) = response.get("token") {
            if let Some(user_token_str) = user_token.as_str() {
                println!("{}", user_token_str);
                if !benchmark {
                    let token_data = json!({
                        "usertoken": user_token_str
                    });
                    fs::write("token.json", token_data.to_string())?;
                }
                return Ok(user_token_str.to_string());
            }
        }
        println!("The response does not contain a 'token' field");
        Ok(String::new())
    }
    pub(crate) async fn get_secrets(
        &self,
        token: &str,
    ) -> anyhow::Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let body = json!({
            "token": token
        });

        let response: Value = client
            .post(self.nks_address)
            .header("accept", "*/*")
            .header("Content-Type", "application/json-patch+json")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        let response_text = response.to_string();

        if let Some(user_token) = response.get("newToken") {
            if let Some(user_token_str) = user_token.as_str() {
                let token_data = json!({
                    "usertoken": user_token_str
                });
                fs::write("token.json", token_data.to_string())?;
            }
        }

        if response_text.is_empty() {
            println!("Received empty response from server");
            Ok(String::new())
        } else {
            let response: Value = serde_json::from_str(&response_text)?;
            let pretty_response = serde_json::to_string_pretty(&response)
                .unwrap_or_else(|_| String::from("Error formatting JSON"));
            Ok(pretty_response)
        }
    }

    pub(crate) async fn add_secrets(
        &self,
        token: &str,
        data: Value,
    ) -> anyhow::Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let body = json!({
            "token": token,
            "data": data
        });

        let response: Value = client
            .post(self.nks_address)
            .header("accept", "*/*")
            .header("Content-Type", "application/json-patch+json")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        //save new token
        if let Some(user_token) = response.get("newToken") {
            if let Some(user_token_str) = user_token.as_str() {
                let token_data = json!({
                    "usertoken": user_token_str
                });
                fs::write("token.json", token_data.to_string())?;
            }
        }

        let pretty_response = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| String::from("Error formatting JSON"));
        println!("{}", pretty_response);

        Ok((pretty_response))
    }

    pub(crate) async fn delete_secrets(&self, token: &str) -> anyhow::Result<(), Error> {
        let client = reqwest::Client::new();
        let body = json!({
            "token": token
        });

        let response: Value = client
            .delete(self.nks_address)
            .header("accept", "*/*")
            .header("Content-Type", "application/json-patch+json")
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        //save new token
        if let Some(user_token) = response.get("newToken") {
            if let Some(user_token_str) = user_token.as_str() {
                let token_data = json!({
                    "usertoken": user_token_str
                });
                fs::write("token.json", token_data.to_string());
            }
        }

        let pretty_response = serde_json::to_string_pretty(&response)
            .unwrap_or_else(|_| String::from("Error formatting JSON"));
        println!("{}", pretty_response);

        Ok(())
    }

    pub(crate) fn get_usertoken_from_file() -> Option<String> {
        let mut file = File::open("token.json").ok()?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).ok()?;

        let json: Value = serde_json::from_str(&contents).ok()?;

        if let Some(usertoken) = json["usertoken"].as_str() {
            return Some(usertoken.to_string());
        } else {
            println!("usertoken not found or invalid format.");
            return None;
        }
    }

    pub(crate) async fn get_and_save_key_pair(
        &self,
        token: &str,
        key_name: &str,
        key_type: &str,
    ) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let request_body = json!(
            {
            "token": token,
            "name": key_name,
            "type": key_type
            }
        );
        println!("body: {}", request_body);

        let response = client
            .post(self.nks_address)
            .header("accept", "*/*")
            .header("Content-Type", "application/json-patch+json")
            .json(&request_body)
            .send()
            .await?;

        let status = response.status(); // Clone the status here
        let response_text = response.text().await?;
        if !status.is_success() {
            println!("Error response:\n{}", response_text);
            return Err(format!("Server returned status code: {}", status).into());
        }

        println!("Success response:\n{}", response_text);
        let response_json: Value = serde_json::from_str(&response_text)?;

        if let Some(user_token) = response_json.get("newToken") {
            if let Some(user_token_str) = user_token.as_str() {
                let token_data = json!({
                    "usertoken": user_token_str
                });
                fs::write("token.json", token_data.to_string())?;
            }
        }
        let pretty_response = serde_json::to_string_pretty(&response_json)
            .unwrap_or_else(|_| String::from("Error formatting JSON"));

        Ok(pretty_response)
    }
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

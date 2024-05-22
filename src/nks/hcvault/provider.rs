use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::string::String;
use std::sync::{Arc, Mutex};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{json, Value};
use serde_json::Value::String as JsonString;
use super::{NksProvider};
use tracing::instrument;
use tokio::runtime::Runtime;

//TODO use CAL once it can compile
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers},
            hashes::Hash,
        },
        KeyUsage,
    },
    error::SecurityModuleError,
    traits::module_provider::Provider,
};
use crate::common::traits::module_provider_config::ProviderConfig;
use crate::nks::NksConfig;


/// Implements the `Provider` trait, providing cryptographic operations utilizing a nks.


impl Provider for NksProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method generates a new cryptographic key within the nks, using the specified
    /// algorithm, symmetric algorithm, hash algorithm, and key usages. The key is made persistent
    /// and associated with the provided `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm to be used with the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    //TODO: implement error handling for when key_id already exists
    fn create_key(&mut self, key_id: &str, config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        if let Some(nks_config) = config.as_any().downcast_ref::<NksConfig>() {
            let runtime = Runtime::new().unwrap();
            let get_and_save_keypair_result = runtime.block_on(get_and_save_key_pair(
                &*nks_config.nks_token.clone(),
                key_id,
                match nks_config.key_algorithm.clone() {
                    AsymmetricEncryption::Rsa(_) => "rsa",
                    AsymmetricEncryption::Ecc(_) => "ecdsa",
                },
                Url::parse(&nks_config.nks_address).unwrap()
            ));
            match get_and_save_keypair_result {
                Ok((result_string, new_token)) => {
                    println!("Key pair generated and saved successfully: {}", result_string);
                    let response: Response = serde_json::from_str(&result_string).unwrap();
                    let key_id = response.data.keys[0].id.clone();
                    self.key_id = key_id;
                    //safe token to config
                    let config = NksConfig::new(
                        new_token.clone(),
                        nks_config.nks_address.clone(),
                        nks_config.key_algorithm.clone(),
                        nks_config.hash.clone(),
                        nks_config.key_usages.clone(),
                    );
                    self.config = Some(config);
                    Ok(())
                }
                Err(err) => {
                    println!("Failed to generate and save key pair: {}", err);
                    Err(SecurityModuleError::NksError)
                }
            }
        } else {
            println!("Failed to downcast to NksConfig");
            Err(SecurityModuleError::NksError)
        }

    }

    fn load_key(&mut self, key_id: &str, config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        todo!()
    }

    /// Initializes the nks module and returns a handle for further operations.
    ///
    /// This method initializes the nks context and prepares it for use. It should be called
    /// before performing any other operations with the nks.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.

    #[instrument]
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        if let Some(nks_config) = self.config.as_ref().unwrap().as_any().downcast_ref::<NksConfig>() {
            //get address and token from config
            let nks_address_str = nks_config.nks_address.clone();
            let nks_address = Some(Url::from_str(nks_address_str.as_str()).unwrap());
            let mut nks_token = nks_config.nks_token.clone();
            if nks_token.is_empty() {
                println!("Token field in config is empty. Generating token...");
                // Token field empty, generate token using API
                let runtime = Runtime::new().unwrap();
                let nks_address = nks_address.clone().ok_or(SecurityModuleError::NksError)?;
                match runtime.block_on(get_token(nks_address.clone())) {
                    Ok(token) => {
                        nks_token = token;
                    }
                    Err(err) => {
                        println!("Failed to get tokens from API: {}", err);
                        return Err(SecurityModuleError::NksError);
                    }
                }
            }
            //store current secrets
            let runtime = tokio::runtime::Runtime::new().unwrap();
            match runtime.block_on(get_secrets(&nks_token.as_str(), &nks_address_str)) {
                Ok((secrets_json, newToken)) => {
                    self.secrets_json = Some(secrets_json.parse().unwrap());
                    nks_token = newToken;
                }
                Err(err) => {
                    println!("Failed to get secrets: {}", err);
                    return Err(SecurityModuleError::NksError);
                }
            }
            //safe token to config
            let config = NksConfig::new(
                nks_token.clone(),
                nks_config.nks_address.clone(),
                nks_config.key_algorithm.clone(),
                nks_config.hash.clone(),
                nks_config.key_usages.clone(),
            );
            self.config = Some(config);

            println!("Nks initialized successfully.");
            println!("Secrets: {:?}", self.secrets_json);
            Ok(())
        } else {
            println!("Failed to downcast to NksConfig");
            Err(SecurityModuleError::NksError)
        }


    }
// impl NksProvider {
    /*TODO
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method generates a new cryptographic key within the nks, using the specified
    /// algorithm, symmetric algorithm, hash algorithm, and key usages. The key is made persistent
    /// and associated with the provided `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm to be used with the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.

    //TODO implement create_key
    #[instrument]
    pub(crate) fn create_key(&mut self, key_id: &str, key_algorithm: AsymmetricEncryption,
                             sym_algorithm: Option<BlockCiphers>,
                             hash: Option<Hash>,
                             key_usages: Vec<KeyUsage>, ) -> Result<(), SecurityModuleError> {
        // Rufen Sie die API auf, um das Token zu erhalten
        let token = Runtime::new().unwrap().block_on((false)).unwrap();

        // Rufen Sie die API auf, um den Schlüssel zu generieren und zu speichern
        let _ = Runtime::new().unwrap().block_on(api::get_and_save_key_pair(&token, key_id, "RSA"));

        // Führen Sie den Rest der Logik aus, um den Schlüssel zu erstellen
        // ...

        Ok(()) // Rückgabe Ok, wenn alles erfolgreich war
    }

    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method loads an existing cryptographic key from the nks, using the specified
    /// algorithm, symmetric algorithm, hash algorithm, and key usages. The loaded key is
    /// associated with the provided `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `key_algorithm` - The asymmetric encryption algorithm used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm used with the key.
    /// * `hash` - An optional hash algorithm used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.

    //TODO implement load_key
    #[instrument]
    pub(crate) fn load_key(&mut self, key_id: &str) -> Result<(), SecurityModuleError> {
        // Rufen Sie die API auf, um das Token zu erhalten
        let token = Runtime::new().unwrap().block_on(api::get_token(false)).unwrap();

        // Führen Sie die Suche nach dem Schlüssel in der API durch und erhalten Sie das Ergebnis
        let key_info = Runtime::new().unwrap().block_on(api::search_key_from_api(&token, key_id)).unwrap();

        // Verarbeiten Sie das Ergebnis und geben Sie es aus
        match key_info {
            Some((public_key, private_key, key_type, length, curve)) => {
                println!("Public Key for key '{}': {}", key_id, public_key);
                println!("Private Key for key '{}': {}", key_id, private_key);
                println!("Type for key '{}': {}", key_id, key_type);
                println!("Length for key '{}': {}", key_id, length);
                match curve {
                    Some(curve) => println!("Curve for key '{}': {}", key_id, curve),
                    None => println!("Curve for key '{}': None", key_id),
                }
            }
            None => println!("Key '{}' not found in API", key_id),
        }

        Ok(()) // Rückgabe Ok, wenn alles erfolgreich war
    }

    /// Initializes the nks module and returns a handle for further operations.
    ///
    /// This method initializes the nks context and prepares it for use. It should be called
    /// before performing any other operations with the nks.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.


    //adresse des nks
    //getsecret
    //json lokal speichern
    //neues token updaten
    //algorithmus checken
    //TODO implement initialize_module
    #[instrument]
    pub(crate) fn initialize_module(
        &mut self,
        nks_address: nks_address,
        nks_token: nks_token,
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<(), SecurityModuleError> {
        self.nks_address = nks_address;
        self.nks_token = nks_token;
        self.key_algorithm = Some(key_algorithm);
        self.sym_algorithm = sym_algorithm;
        self.hash = hash;
        self.key_usages = Some(key_usages);
        // Check if tokens file exists
        let tokens_file_path = "path/to/tokens_file"; // Adjust the path as needed
        if Path::new(&tokens_file_path).exists() {
            println!("Tokens file exists.");
            // Tokens file exists, do something
        } else {
            println!("Tokens file does not exist. Generating tokens...");
            // Tokens file does not exist, generate tokens using API
            match api::get_token() {
                Ok(tokens) => {
                    // Save tokens to file
                    if let Err(err) = save_tokens_to_file(&tokens_file_path, &tokens) {
                        println!("Failed to save tokens to file: {}", err);
                        return Err(SecurityModuleError::TokenFileError);
                    }
                    println!("Token safed sucessfully");
                }
                Err(err) => {
                    println!("Failed to get tokens from API: {}", err);
                    return Err(SecurityModuleError::TokenGenerationError);
                }
            }
        }
        Ok(())
    }*/
}

#[derive(Deserialize)]
struct Key {
    id: String,
    #[serde(rename = "type")]
    key_type: String,
    publicKey: String,
    privateKey: String,
    length: String,
    curve: Option<String>,
}

#[derive(Deserialize)]
struct Data {
    keys: Vec<Key>,
    signatures: Vec<Value>,
}

#[derive(Deserialize)]
struct Response {
    data: Data,
    newToken: String,
}

// fn get_usertoken_from_file() -> Option<String> {
//     let mut file = File::open("token.json").ok()?;
//     let mut contents = String::new();
//     file.read_to_string(&mut contents).ok()?;
//
//     let json: Value = serde_json::from_str(&contents).ok()?;
//
//     if let Some(usertoken) = json["usertoken"].as_str() {
//         return Some(usertoken.to_string());
//     } else {
//         println!("usertoken not found or invalid format.");
//         return None;
//     }
// }

async fn get_token(nks_address: Url) -> anyhow::Result<String, Box<dyn std::error::Error>> {
    let api_url = nks_address.join("getToken");
    let response: Value = reqwest::Client::new()
        .get(api_url.unwrap())
        .header("accept", "*/*")
        .send()
        .await?
        .json()
        .await?;

    if let Some(user_token) = response.get("token") {
        if let Some(user_token_str) = user_token.as_str() {
            let token_data = json!({
                "usertoken": user_token_str
            });
            return Ok(user_token_str.to_string());
        }
    }
    println!("The response does not contain a 'token' field");
    Ok(String::new())
}

async fn get_and_save_key_pair(
    token: &str,
    key_name: &str,
    key_type: &str,
    nks_address: Url,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let request_body = json!(
            {
            "token": token,
            "name": key_name,
            "type": key_type
            }
        );
    println!("body: {}", request_body);
    let api_url = nks_address.join("generateAndSaveKeyPair");
    let response = client
        .post(api_url.unwrap())
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

    //save new token
    let user_token = response_json.get("newToken").unwrap().as_str().unwrap().to_string();

    Ok((response_text, user_token))
}

async fn get_secrets(token: &str, nks_address_str: &str) -> anyhow::Result<(String, String), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let body = json!({
        "token": token
    });

    let response: Value = client.post(format!("{}getSecrets", nks_address_str))
        .header("accept", "*/*")
        .header("Content-Type", "application/json-patch+json")
        .json(&body)
        .send()
        .await?
        .json()
        .await?;

    let response_text = response.to_string();

    //save new token
    let user_token = response.get("newToken").unwrap().as_str().unwrap().to_string();

    // Extract the data field from the response
    let data = response.get("data").ok_or_else(|| "Data field not found in the response")?;

    // Convert the data field back to a string
    let data_str = serde_json::to_string_pretty(data)?;

    Ok((data_str, user_token))
}

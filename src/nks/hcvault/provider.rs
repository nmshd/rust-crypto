use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{json, Value};
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
    fn create_key(&mut self, key_id: &str, config: Box<dyn ProviderConfig>) -> Result<(), SecurityModuleError> {
        let runtime = Runtime::new().unwrap();
        let get_and_save_keypair_result = runtime.block_on(get_and_save_key_pair(
            &*self.nks_token.clone().unwrap(),
            key_id,
            match self.key_algorithm.clone().unwrap() {
                AsymmetricEncryption::Rsa(_) => "rsa",
                AsymmetricEncryption::Ecc(_) => "ecdsa",
            },
            self.nks_address.clone().unwrap(),
        ));
        match get_and_save_keypair_result {
            Ok(result_string) => {
                let response: Response = serde_json::from_str(&result_string).unwrap();
                let key_id = response.data.keys[0].id.clone();
                self.key_id = key_id;
                Ok(())
            }
            Err(err) => {
                println!("Failed to generate and save key pair: {}", err);
                Err(SecurityModuleError::NksError)
            }
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


    //adresse des nks
    //getsecret
    //json lokal speichern
    //neues token updaten
    //algorithmus checken
    //TODO implement initialize_module
    #[instrument]
    fn initialize_module(
        &mut self,
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<(), SecurityModuleError> {
        self.nks_address = Some(Url::from_str("http://localhost:5272/apidemo/").unwrap()); //TODO: find solution with nks_address not hardcoded
        self.key_algorithm = Some(key_algorithm);
        self.sym_algorithm = sym_algorithm;
        self.hash = hash;
        self.key_usages = Some(key_usages);
        // Check if token file exists
        let tokens_file_path = Box::new(Path::new("token.json")); // Adjust the path as needed
        if Path::new(&*tokens_file_path).exists() {
            println!("Tokens file exists.");
            self.nks_token = get_usertoken_from_file();
        } else {
            println!("Tokens file does not exist. Generating tokens...");
            // Token file does not exist, generate token using API
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let nks_address = self.nks_address.clone().ok_or(SecurityModuleError::NksError)?;
            match runtime.block_on(get_token(self.nks_address.clone().unwrap(), tokens_file_path)) {
                Ok(token) => {
                    self.nks_token = Option::from(token);
                }
                Err(err) => {
                    println!("Failed to get tokens from API: {}", err);
                    return Err(SecurityModuleError::NksError);
                }
            }
        }
        Ok(())
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
    curve: String,
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

fn get_usertoken_from_file() -> Option<String> {
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

async fn get_token(nks_address: Url, token_path: Box<&Path>) -> anyhow::Result<String, Box<dyn std::error::Error>> {
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
            fs::write(token_path.as_ref(), token_data.to_string().as_bytes())?;
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

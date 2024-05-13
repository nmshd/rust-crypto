use super::NksProvider;
use tracing::instrument;

//TODO use CAL once it can compile
use crate::common::{
    crypto::algorithms::encryption::AsymmetricEncryption, error::SecurityModuleError,
    traits::key_handle::KeyHandle,
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
    /*
    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
    }

     */

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
    fn encrypt_data(&self, data: &[u8], ) -> Result<Vec<u8>, SecurityModuleError> {

    }


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

    //TODO implement verify_signature
    #[instrument]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {}



    pub(crate) async fn get_token(&self, benchmark: bool) -> anyhow::Result<String, Box<dyn std::error::Error>> {
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
    pub(crate) async fn get_secrets(&self, token: &str) -> anyhow::Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let body = json!({
        "token": token
    });

        let response: Value = client.post(self.nks_address)
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
            let pretty_response = serde_json::to_string_pretty(&response).unwrap_or_else(|_| String::from("Error formatting JSON"));
            Ok(pretty_response)
        }
    }

    pub(crate) async fn add_secrets(&self, token: &str, data: Value) -> anyhow::Result<String, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let body = json!({
        "token": token,
        "data": data
    });

        let response: Value = client.post(self.nks_address)
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

        let pretty_response = serde_json::to_string_pretty(&response).unwrap_or_else(|_| String::from("Error formatting JSON"));
        println!("{}", pretty_response);

        Ok((pretty_response))
    }

    pub(crate) async fn delete_secrets(&self, token: &str) -> anyhow::Result<(), Error> {
        let client = reqwest::Client::new();
        let body = json!({
        "token": token
    });

        let response: Value = client.delete(self.nks_address)
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

        let pretty_response = serde_json::to_string_pretty(&response).unwrap_or_else(|_| String::from("Error formatting JSON"));
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

    pub(crate) async fn get_and_save_key_pair(&self, token: &str, key_name: &str, key_type: &str) -> std::result::Result<String, Box<dyn std::error::Error>> {
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

use std::sync::{Arc, Mutex};
use super::{api, NksProvider};
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


/// Implements the `Provider` trait, providing cryptographic operations utilizing a nks.


//impl Provider for NksProvider {
impl NksProvider {
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
        let token = Runtime::new().unwrap().block_on(api::get_token(false)).unwrap();

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
    }
}

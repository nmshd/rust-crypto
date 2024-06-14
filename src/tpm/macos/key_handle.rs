extern crate apple_secure_enclave_bindings;
use super::{provider::{convert_algorithms, convert_hash}, SecureEnclaveProvider};
use crate::common::{error::SecurityModuleError, traits::key_handle::KeyHandle};
use tracing::instrument;


/// Provides cryptographic operations for asymmetric keys on macOS,
/// such as signing, encryption, decryption, and signature verification.
impl KeyHandle for SecureEnclaveProvider {
    /// Signs the given data using the cryptographic key managed by the Secure Enclave provider.
    /// 
    /// Uses the rust_crypto_call_sign_data function from the Swift Secure Enclave bindings.
    ///
    /// # Arguments
    ///
    /// * `data` - A byte slice representing the data to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec())
            .map_err(|_| SecurityModuleError::SigningError("Data conversion error".to_string()))?;
        
        let key_id = &self.key_id; 
        let config = self.config.as_ref().ok_or(SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?;
        let algo = convert_algorithms(config.clone());
        let hash = convert_hash(config.hash.expect("No Hash given"));

        let signed_data = apple_secure_enclave_bindings::keyhandle::rust_crypto_call_sign_data(key_id.clone(), string_data, algo, hash);

        if signed_data.0 {
            Err(SecurityModuleError::EncryptionError(
                        signed_data.1.to_string(),
                    ))
        } else {
            Ok(signed_data.1.into_bytes())
        }
    }


    /// Decrypts the given encrypted data using the cryptographic key managed by the Secure Enclave provider.
    /// 
    /// Uses the rust_crypto_call_decrypt_data function from the Swift Secure Enclave bindings.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(encrypted_data.to_vec()).map_err(|_| {
            SecurityModuleError::DecryptionError("Data conversion error".to_string())
        })?;
        let config = self.config.as_ref().ok_or(SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?;
        let algorithm = convert_algorithms(config.clone()); 
        let hash = convert_hash(config.hash.expect("No Hash given"));

        let decrypted_data =
            apple_secure_enclave_bindings::keyhandle::rust_crypto_call_decrypt_data(self.key_id.to_string(), string_data, algorithm, hash);


        if decrypted_data.0 {
            Err(SecurityModuleError::EncryptionError(
                decrypted_data.1.to_string(),
                ))
        } else {
            Ok(decrypted_data.1.into_bytes())
        }
    }


    /// Encrypts data with the cryptographic key.
    ///
    /// Uses the rust_crypto_call_encrypt_data function from the Swift Secure Enclave bindings.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| {
            SecurityModuleError::EncryptionError("Data conversion error".to_string())
        })?;
        let key_id = &self.key_id;
        let config = self.config.as_ref().ok_or(SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?;
        let algorithm = convert_algorithms(config.clone()); 
        let hash = convert_hash(config.hash.expect("No Hash given"));

        let encrypted_data =
            apple_secure_enclave_bindings::keyhandle::rust_crypto_call_encrypt_data(key_id.to_string(), string_data, algorithm, hash);


        if encrypted_data.0 {
            Err(SecurityModuleError::EncryptionError(
                encrypted_data.1.to_string(),
                ))
        } else {
            Ok(encrypted_data.1.into_bytes())
        }
    }


    /// Verifies the signature of the given data using the cryptographic key managed by the Secure Enclave provider.
    /// 
    /// Uses the rust_crypto_call_verify_signature function from the Swift Secure Enclave bindings.
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
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| {
            SecurityModuleError::SignatureVerificationError("Data conversion error".to_string())
        })?;

        let string_signature = String::from_utf8(signature.to_vec()).map_err(|_| {
            SecurityModuleError::SignatureVerificationError("Signature conversion error".to_string(),)
        })?;

        let key_id = &self.key_id;  
        let config = self.config.as_ref().ok_or(SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?;
        let algo = convert_algorithms(config.clone()); 
        let hash = convert_hash(config.hash.expect("No Hash given"));

        let verification_result =
            apple_secure_enclave_bindings::keyhandle::rust_crypto_call_verify_signature(key_id.clone(), string_data, string_signature, algo, hash);

        // The FFI bridge always returns strings by design.
        // If not "true" or "false" is found, an error from the function is expected
        match verification_result.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(SecurityModuleError::SignatureVerificationError(
                verification_result,
            )),
        }
    }
}


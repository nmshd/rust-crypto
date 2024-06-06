extern crate apple_secure_enclave_bindings;
use super::SecureEnclaveProvider;
use crate::{
    common::{error::SecurityModuleError, traits::key_handle::KeyHandle}, tpm::macos::provider::convert_sign_algorithms,
};
use tracing::instrument;
use regex::Regex;

impl KeyHandle for SecureEnclaveProvider {
    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let _string_data = String::from_utf8(data.to_vec())
            .map_err(|_| SecurityModuleError::SigningError("Data conversion error".to_string()))?;
        
        let key_id = &self.key_id; 
        let config = self.config.as_ref().ok_or(SecurityModuleError::InitializationError(("Failed to initialize config").to_owned()))?;
        let algo = convert_sign_algorithms(config.clone()); 

        // Debug TODO
        // println!("\nSignData: Send to Swift | key_id: {} | StringData: {} | Algorithm: {}", key_id, _string_data, algo); 
        let signed_data = apple_secure_enclave_bindings::keyhandle::rust_crypto_call_sign_data(key_id.clone(), _string_data, algo);

        // Debug TODO
        // println!("\nSignData: Recieved from Swift: {}", signed_data); 

        if Regex::new("(?i)error")
            .unwrap()
            .is_match(signed_data.as_str())
        {
            Err(SecurityModuleError::EncryptionError(
                signed_data.to_string(),
            ))
        } else {
            Ok(signed_data.into_bytes())
        }
    }

    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(encrypted_data.to_vec()).map_err(|_| {
            SecurityModuleError::DecryptionError("Data conversion error".to_string())
        })?;

        let decrypted_data =
            apple_secure_enclave_bindings::keyhandle::rust_crypto_call_decrypt_data(self.key_id.to_string(), string_data);

        if Regex::new("(?i)error")
            .unwrap()
            .is_match(decrypted_data.as_str())
        {
            Err(SecurityModuleError::EncryptionError(
                decrypted_data.to_string(),
            ))
        } else {
            Ok(decrypted_data.into_bytes())
        }
    }

    #[instrument]
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| {
            SecurityModuleError::EncryptionError("Data conversion error".to_string())
        })?;
        let key_id = &self.key_id;

        //Debug TODO
        // println!("\nEncryptData: Send to Swift | key_id: {} | data: {}", key_id.clone(), string_data); 

        let encrypted_data =
            apple_secure_enclave_bindings::keyhandle::rust_crypto_call_encrypt_data(key_id.to_string(), string_data);

        //Debug TODO
        // println!("\nEncryptData: Recieved from Swift data: {}", encrypted_data); 
        
        if Regex::new("(?i)error")
            .unwrap()
            .is_match(encrypted_data.as_str())
        {
            Err(SecurityModuleError::EncryptionError(
                encrypted_data.to_string(),
            ))
        } else {
            Ok(encrypted_data.into_bytes())
        }
    }

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
        let algo = convert_sign_algorithms(config.clone()); 

        // Debug TODO
        // println!("VerifyData: Send to Swift | key_id: {} | string_data: {} | string_signature: {} ",key_id.clone(), string_data, string_signature);

        let verification_result =
            apple_secure_enclave_bindings::keyhandle::rust_crypto_call_verify_signature(key_id.clone(), string_data, string_signature, algo);

        // The FFI bridge always returns strings by design.
        // If not "true" or "false" is found, we expect an error from the function
        match verification_result.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(SecurityModuleError::SignatureVerificationError(
                verification_result,
            )),
        }
    }
}

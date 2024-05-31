impl KeyHandle for TpmProvider {

    #[instrument] 
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| SecurityModuleError::SigningError("Data conversion error".to_string()))?;
        let signed_data = ffi::rustcall_sign_data(string_data, "3344".to_string());

        
        // The FFI bridge always returns strings by design.
        // Therefore, we need to search for the case-insensitive string "error".
        // If "error" is found, we return an error to the function.
        if Regex::new("(?i)error").unwrap().is_match(signed_data.as_str()) {
            Err(SecurityModuleError::EncryptionError(signed_data.to_string()))
        } else {
            Ok(signed_data.into_bytes())
        }
    }

    #[instrument] 
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(encrypted_data.to_vec()).map_err(|_| SecurityModuleError::DecryptionError("Data conversion error".to_string()))?;
        let decrypted_data = ffi::rustcall_decrypt_data(string_data, "3344".to_string());
    
        // The FFI bridge always returns strings by design.
        // Therefore, we need to search for the case-insensitive string "error".
        // If "error" is found, we return an error to the function.
        if Regex::new("(?i)error").unwrap().is_match(decrypted_data.as_str()) {
            Err(SecurityModuleError::EncryptionError(decrypted_data.to_string()))
        } else {
            Ok(decrypted_data.into_bytes())
        }
    }

    #[instrument] 
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| SecurityModuleError::EncryptionError("Data conversion error".to_string()))?;
        let encrypted_data = ffi::rustcall_encrypt_data(string_data, "3344".to_string());

        // The FFI bridge always returns strings by design.
        // Therefore, we need to search for the case-insensitive string "error".
        // If "error" is found, we return an error to the function.
        if Regex::new("(?i)error").unwrap().is_match(encrypted_data.as_str()) {
            Err(SecurityModuleError::EncryptionError(encrypted_data.to_string()))
        } else {
            Ok(encrypted_data.into_bytes())
        }
    }

    #[instrument] 
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| SecurityModuleError::SignatureVerificationError("Data conversion error".to_string()))?;
        let string_signature = String::from_utf8(signature.to_vec()).map_err(|_| SecurityModuleError::SignatureVerificationError("Signature conversion error".to_string()))?;

        let verification_result = ffi::rustcall_verify_data(string_data, string_signature, "3344".to_string());

        
        // The FFI bridge always returns strings by design.
        // If not "true" or "false" is found, we expect an error from the function
        match verification_result.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(SecurityModuleError::SignatureVerificationError(verification_result.as_str())),
        }
    }

}

#[swift_bridge::bridge]
pub mod ffi {
    extern "Swift" {
        fn rustcall_create_key(privateKeyName: String) -> String;
        fn initializeModule() -> bool;
        fn rustcall_load_key(keyID: String) -> String;
        fn rustcall_encrypt_data(data: String, publicKeyName: String) -> String;
        fn rustcall_decrypt_data(data: String, privateKeyName: String) -> String;
        fn rustcall_sign_data(data: String, privateKeyName: String) -> String;
        fn rustcall_verify_data(data: String, signature: String, publicKeyName: String) -> String;
    }
}

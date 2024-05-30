impl KeyHandle for TpmProvider {
    #[instrument] // Fertig
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec())
            .map_err(|_| SecurityModuleError::SigningError("Data conversion error".to_string()))?;
        let signed_data = ffi::rustcall_sign_data(string_data, "3344".to_string());
        Ok(signed_data.into_bytes())
    }

    #[instrument] // Fertig
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(encrypted_data.to_vec()).map_err(|_| {
            SecurityModuleError::DecryptionError("Data conversion error".to_string())
        })?;
        let decrypted_data = ffi::rustcall_decrypt_data(string_data, "3344".to_string());
        Ok(decrypted_data.into_bytes())
    }

    #[instrument] // Fertig
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| {
            SecurityModuleError::EncryptionError("Data conversion error".to_string())
        })?;
        let encrypted_data = ffi::rustcall_encrypt_data(string_data, "3344".to_string());
        Ok(encrypted_data.into_bytes())
    }

    #[instrument] // Fertig, muss ich aber debuggen, ich weiß nicht was als Rückgabe von rustcall_verify_data kommt.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        let string_data = String::from_utf8(data.to_vec()).map_err(|_| {
            SecurityModuleError::SignatureVerificationError("Data conversion error".to_string())
        })?;
        let string_signature = String::from_utf8(signature.to_vec()).map_err(|_| {
            SecurityModuleError::SignatureVerificationError(
                "Signature conversion error".to_string(),
            )
        })?;

        let verification_result =
            ffi::rustcall_verify_data(string_data, string_signature, "3344".to_string());

        match verification_result.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(SecurityModuleError::SignatureVerificationError(
                "Failed to verify the signature".to_string(),
            )),
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

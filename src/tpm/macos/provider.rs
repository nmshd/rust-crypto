impl Provider for TpmProvider {
    #[instrument]
    fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        //wie die anderen Teams es gemacht haben mit config und in module_privider_config.rs:
        //let config = match config.as_any().downcast_ref::<Config>()

        //welcher Error?
        //let string_key_id = String::from_utf8(key_id.map_err(|_| SecurityModuleError::Error("Key ID conversion error".to_string())))?;
        let keypair = ffi::rustcall_create_key(&key_id.to_string());

        if Regex::new("(?i)error").unwrap().ismatch(keypair.as_str()) {
            Err(SecurityModuleError::Error(keypair.to_string()));
        } else {
            Ok(())
        }
    }

    #[instrument]
    fn load_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        //wie die anderen Teams es gemacht haben mit config und in module_privider_config.rs:
        //let config = match config.as_any().downcast_ref::<Config>()
        let private_key = ffi::rustcall_load_key(&key_id.to_string());

        //welcher Error?
        if Regex::new("(?i)error")
            .unwrap()
            .ismatch(private_key.as_str())
        {
            Err(SecurityModuleError::Error(private_key.to_string()));
        } else {
            Ok(())
        }
    }

    #[instrument]
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        let initialization_result = ffi::initializeModule();

        match initialization_result.as_str() {
            "true" => Ok(),
            "false" => Err(SecurityModuleError::InitializationError(
                "Failed to initialize module".to_string(),
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

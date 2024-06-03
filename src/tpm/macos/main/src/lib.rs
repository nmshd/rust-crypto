#[swift_bridge::bridge]
pub mod ffi {
    // Swift-Methods can be used in Rust
    extern "Swift" {
        //Provider operations
        fn initializeModule() -> bool;
        fn rustcall_create_key(key_id: String, key_algorithm_type: String) -> String;
        fn rustcall_load_key(keyID: String) -> String;

        //Keyhandle operations
        fn rustcall_encrypt_data(data: String, publicKeyName: String) -> String;
        fn rustcall_decrypt_data(data: String, privateKeyName: String) -> String;
        fn rustcall_sign_data(data: String, privateKeyName: String) -> String;
        fn rustcall_verify_data(data: String, signature: String, publicKeyName: String) -> String;
    }
}

/**
 *
 *
 *
 */
pub mod provider {
    use crate::ffi;

    pub fn rust_crypto_call_create_key(key_id: String, key_algorithm_type: String) -> String {
        ffi::rustcall_create_key(key_id, key_algorithm_type)
    }

    pub fn rust_crypto_call_load_key() -> String {
        // ffi::rustcall_load_key("3344".to_string());
        todo!();
    }

    pub fn rust_crypto_call_initialize_module() -> bool {
        ffi::initializeModule()
    }
}

pub mod keyhandle {
    pub fn rust_crypto_call_encrypt_data() -> String {
        todo!();
    }

    pub fn rust_crypto_call_decrypt_data() -> String {
        todo!();
    }

    pub fn rust_crypto_call_sign_data() -> String {
        todo!();
    }

    pub fn rust_crypto_call_verify_signature() -> String {
        todo!();
    }
}

#[swift_bridge::bridge]
pub mod ffi {
    // Swift-Methods can be used in Rust
    extern "Swift" {
        //Provider operations
        fn initializeModule() -> bool;
        fn rustcall_create_key(key_id: String, key_algorithm_type: String) -> String;
        fn rustcall_load_key(keyID: String) -> String;

        //Keyhandle operations
        fn rustcall_encrypt_data(key_id: String, data: String) -> String;
        fn rustcall_decrypt_data(key_id: String, data: String) -> String;
        fn rustcall_sign_data(key_id: String, data: String, algo: String) -> String;
        fn rustcall_verify_data(key_id: String, data: String, signature: String, algo: String) -> String;
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

    pub fn rust_crypto_call_load_key(key_id: String) -> String {
        ffi::rustcall_load_key(key_id)
    }

    pub fn rust_crypto_call_initialize_module() -> bool {
        ffi::initializeModule()
    }
}

pub mod keyhandle {
    use crate::ffi;
    pub fn rust_crypto_call_encrypt_data(key_id: String, data: String) -> String {
        ffi::rustcall_encrypt_data(key_id, data)
    }

    pub fn rust_crypto_call_decrypt_data(key_id: String, data: String) -> String {
        ffi::rustcall_decrypt_data(key_id, data)
    }

    pub fn rust_crypto_call_sign_data(key_id: String, data: String, algo: String) -> String {
        ffi::rustcall_sign_data(key_id, data, algo)
    }

    pub fn rust_crypto_call_verify_signature(key_id: String, string_data: String, string_signature: String, algo: String) -> String {
        ffi::rustcall_verify_data(key_id, string_data, string_signature, algo)
    }
}

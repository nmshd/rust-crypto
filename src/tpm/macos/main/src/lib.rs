#[swift_bridge::bridge]
pub mod ffi {
    // Swift-Methods can be used in Rust
    extern "Swift" {
        //Provider operations
        fn initialize_module() -> bool;
        fn rustcall_create_key(key_id: String, key_type: String) -> String;
        fn rustcall_load_key(key_id: String, key_type: String, hash: String) -> String;

        //Keyhandle operations
        fn rustcall_encrypt_data(key_id: String, data: String, algorithm: String, hash: String) -> (bool, String);
        fn rustcall_decrypt_data(key_id: String, data: String, algorithm: String, hash: String) -> (bool, String);
        fn rustcall_sign_data(key_id: String, data: String, algorithm: String, hash: String) -> (bool, String);
        fn rustcall_verify_data(key_id: String, data: String, signature: String, algorithm: String, hash: String) -> String;
    }
}

/**
 *
 *
 *
 */
pub mod provider {
    use crate::ffi;

    pub fn rust_crypto_call_create_key(key_id: String, key_type: String) -> String {
        ffi::rustcall_create_key(key_id, key_type)
    }

    pub fn rust_crypto_call_load_key(key_id: String, key_type: String, hash: String) -> String {
        ffi::rustcall_load_key(key_id, key_type, hash)
    }

    pub fn rust_crypto_call_initialize_module() -> bool {
        ffi::initialize_module()
    }
}

pub mod keyhandle {
    use crate::ffi;
    pub fn rust_crypto_call_encrypt_data(key_id: String, data: String, algorithm: String, hash: String) -> (bool, String) {
        ffi::rustcall_encrypt_data(key_id, data, algorithm, hash)
    }

    pub fn rust_crypto_call_decrypt_data(key_id: String, data: String, algorithm: String, hash: String) -> (bool, String) {
        ffi::rustcall_decrypt_data(key_id, data, algorithm, hash)
    }

    pub fn rust_crypto_call_sign_data(key_id: String, data: String, algorithm: String, hash: String) -> (bool, String) {
        ffi::rustcall_sign_data(key_id, data, algorithm, hash)
    }

    pub fn rust_crypto_call_verify_signature(key_id: String, string_data: String, string_signature: String, algorithm: String, hash: String) -> String {
        ffi::rustcall_verify_data(key_id, string_data, string_signature, algorithm, hash)
    }
}

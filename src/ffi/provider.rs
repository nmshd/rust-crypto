use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers},
            hashes::Hash,
        },
        KeyUsage,
    },
    traits::{key_handle::KeyHandle, module_provider::Provider},
};
use std::{
    ffi::CStr,
    os::raw::c_char,
    sync::{Arc, Mutex},
};

#[repr(C)]
pub struct ProviderFFI {
    pub provider: *mut dyn Provider,
    pub key_handle: Option<*mut dyn KeyHandle>,
}

impl ProviderFFI {
    /// Create a new ProviderFFI instance from a raw pointer to a Provider trait object.
    /// # Safety
    /// The caller must ensure that the provider pointer is valid and that the ProviderFFI
    /// takes ownership of the pointer. The ProviderFFI is responsible for the proper
    /// deallocation of the provider.
    #[no_mangle]
    pub unsafe fn new(provider: Arc<Mutex<dyn Provider>>) -> *mut ProviderFFI {
        Box::into_raw(Box::new(ProviderFFI {
            provider: (&mut *provider.lock().unwrap()) as *mut dyn Provider,
            key_handle: None,
        }))
    }
}

/// Initialize the security module using the provider
/// # Safety
/// This function assumes the provider pointer and the key_usages pointer are valid.
/// It is unsafe because it involves raw pointer dereferencing and assumes the provided
/// array is valid for the given length.
#[no_mangle]
pub unsafe extern "C" fn initialize_module(
    provider_ffi: *mut ProviderFFI,
    key_algorithm: AsymmetricEncryption,
    sym_algorithm: BlockCiphers,
    hash: Hash,
    key_usages: *const KeyUsage,
    key_usages_len: usize,
) -> i32 {
    if provider_ffi.is_null() || key_usages.is_null() {
        return -1; // Error handling for null pointer
    }

    let provider_ffi = &mut *provider_ffi;
    let key_usages_slice = std::slice::from_raw_parts(key_usages, key_usages_len);

    match (*provider_ffi.provider).initialize_module(
        key_algorithm,
        Some(sym_algorithm),
        Some(hash),
        key_usages_slice.to_vec(),
    ) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Creates a new cryptographic key
/// # Safety
/// The function assumes that the key_id pointer is valid and points to a valid C string.
#[no_mangle]
pub unsafe extern "C" fn create_key(provider_ffi: *mut ProviderFFI, key_id: *const c_char) -> i32 {
    if provider_ffi.is_null() || key_id.is_null() {
        return -1; // Error handling for null pointer
    }

    let provider = &mut *provider_ffi;
    let key_id_cstr = CStr::from_ptr(key_id);

    let key_id_str = match key_id_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1, // Error handling for invalid UTF-8
    };

    match (*provider.provider).create_key(key_id_str) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Loads an existing cryptographic key
/// # Safety
/// The function assumes that the key_id pointer is valid and points to a valid C string.
#[no_mangle]
pub unsafe extern "C" fn load_key(provider_ffi: *mut ProviderFFI, key_id: *const c_char) -> i32 {
    if provider_ffi.is_null() || key_id.is_null() {
        return -1; // Error handling for null pointer
    }

    let provider = &mut *provider_ffi;
    let key_id_cstr = CStr::from_ptr(key_id);

    let key_id_str = match key_id_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1, // Error handling for invalid UTF-8
    };

    match (*provider.provider).load_key(key_id_str) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Signs data using the cryptographic key.
/// # Safety
/// Assumes `provider_ffi` is a valid pointer to an object implementing `KeyHandle`.
#[no_mangle]
pub unsafe extern "C" fn key_handle_sign_data(
    provider_ffi: *mut ProviderFFI,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_capacity: usize,
    actual_output_len: *mut usize,
) -> i32 {
    if provider_ffi.is_null() || data.is_null() || output.is_null() || actual_output_len.is_null() {
        return -1; // Error handling for null pointer
    }

    let provider = &mut *provider_ffi;
    let key_handle = &*provider.key_handle.unwrap();
    let data_slice = std::slice::from_raw_parts(data, data_len);

    match key_handle.sign_data(data_slice) {
        Ok(signature) => {
            if signature.len() > output_capacity {
                return -2; // Buffer too small
            }
            std::ptr::copy_nonoverlapping(signature.as_ptr(), output, signature.len());
            *actual_output_len = signature.len();
            0 // Success
        }
        Err(_) => -3, // Operation failed
    }
}

/// Encrypts data using the cryptographic key.
/// # Safety
/// Assumes `provider_ffi` is a valid pointer to an object implementing `KeyHandle`.
#[no_mangle]
pub unsafe extern "C" fn key_handle_encrypt_data(
    provider_ffi: *mut ProviderFFI,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_capacity: usize,
    actual_output_len: *mut usize,
) -> i32 {
    if provider_ffi.is_null() || data.is_null() || output.is_null() || actual_output_len.is_null() {
        return -1; // Error handling for null pointer
    }

    let provider = &mut *provider_ffi;
    let key_handle = &*provider.key_handle.unwrap();
    let data_slice = std::slice::from_raw_parts(data, data_len);

    match key_handle.encrypt_data(data_slice) {
        Ok(encrypted_data) => {
            if encrypted_data.len() > output_capacity {
                return -2; // Buffer too small
            }
            std::ptr::copy_nonoverlapping(encrypted_data.as_ptr(), output, encrypted_data.len());
            *actual_output_len = encrypted_data.len();
            0 // Success
        }
        Err(_) => -3, // Operation failed
    }
}

/// Verifies the signature of given data.
/// # Safety
/// Assumes `provider_ffi` is a valid pointer to an object implementing `KeyHandle`.
#[no_mangle]
pub unsafe extern "C" fn key_handle_verify_signature(
    provider_ffi: *mut ProviderFFI,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    if provider_ffi.is_null() || data.is_null() || signature.is_null() {
        return -1; // Error handling for null pointer
    }

    let provider = &mut *provider_ffi;
    let key_handle = &*provider.key_handle.unwrap();
    let data_slice = std::slice::from_raw_parts(data, data_len);
    let signature_slice = std::slice::from_raw_parts(signature, signature_len);

    match key_handle.verify_signature(data_slice, signature_slice) {
        Ok(valid) => {
            if valid {
                0
            } else {
                -3
            }
        } // 0 for valid, -3 for invalid signature
        Err(_) => -2, // Operation failed
    }
}

/// Free the ProviderFFI instance.
/// # Safety
/// This function is unsafe as it requires the caller to ensure that the pointer is valid
/// and that it has not been freed previously.
#[no_mangle]
pub unsafe extern "C" fn provider_ffi_free(ptr: *mut ProviderFFI) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr); // Automatically drop and deallocate
    }
}

use crate::common::traits::key_handle::KeyHandle;
use async_std::sync::Mutex;
use std::sync::Arc;

pub struct KeyHandleFFI {
    key_handle: Arc<Mutex<dyn KeyHandle>>,
}

// impl KeyHandleFFI {
//     /// Create a new KeyHandleFFI instance from an Arc<Mutex<dyn KeyHandle>>.
//     /// This function is for internal use only and not exposed through the FFI.
//     pub(crate) fn new(key_handle: Arc<Mutex<dyn KeyHandle>>) -> *mut KeyHandleFFI {
//         Box::into_raw(Box::new(KeyHandleFFI { key_handle }))
//     }
// }

/// Signs data using the cryptographic key.
/// # Safety
/// Assumes `key_handle_ffi` is a valid pointer to an object implementing `KeyHandle`.
#[no_mangle]
pub unsafe extern "C" fn key_handle_sign_data(
    key_handle_ffi: *mut KeyHandleFFI,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_capacity: usize,
    actual_output_len: *mut usize,
) -> i32 {
    if key_handle_ffi.is_null() || data.is_null() || output.is_null() || actual_output_len.is_null()
    {
        return -1; // Error handling for null pointer
    }

    // Safely access the key handle and lock the mutex
    let key_handle = &(*key_handle_ffi).key_handle;
    let key_handle_guard = async_std::task::block_on(key_handle.lock());

    let data_slice = std::slice::from_raw_parts(data, data_len);

    // Synchronously handle the async sign_data call using block_on
    let result = async_std::task::block_on(key_handle_guard.sign_data(data_slice));

    match result {
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
/// Assumes `key_handle_ffi` is a valid pointer to an object implementing `KeyHandle`.
#[no_mangle]
pub unsafe extern "C" fn key_handle_encrypt_data(
    key_handle_ffi: *mut KeyHandleFFI,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    output_capacity: usize,
    actual_output_len: *mut usize,
) -> i32 {
    if key_handle_ffi.is_null() || data.is_null() || output.is_null() || actual_output_len.is_null()
    {
        return -1; // Error handling for null pointer
    }

    // Safely access the key handle and lock the mutex
    let key_handle = &(*key_handle_ffi).key_handle;
    let key_handle_guard = async_std::task::block_on(key_handle.lock());

    let data_slice = std::slice::from_raw_parts(data, data_len);

    // Synchronously handle the async encrypt_data call using block_on
    let result = async_std::task::block_on(key_handle_guard.encrypt_data(data_slice));

    match result {
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
/// Assumes `key_handle_ffi` is a valid pointer to an object implementing `KeyHandle`.
#[no_mangle]
pub unsafe extern "C" fn key_handle_verify_signature(
    key_handle_ffi: *mut KeyHandleFFI,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    if key_handle_ffi.is_null() || data.is_null() || signature.is_null() {
        return -1; // Error handling for null pointer
    }

    // Safely access the key handle and lock the mutex
    let key_handle = &(*key_handle_ffi).key_handle;
    let key_handle_guard = async_std::task::block_on(key_handle.lock());

    let data_slice = std::slice::from_raw_parts(data, data_len);
    let signature_slice = std::slice::from_raw_parts(signature, signature_len);

    // Synchronously handle the async verify_signature call using block_on
    let result =
        async_std::task::block_on(key_handle_guard.verify_signature(data_slice, signature_slice));

    match result {
        Ok(valid) => {
            if valid {
                0 // Signature is valid
            } else {
                -3 // Signature is invalid
            }
        }
        Err(_) => -2, // Operation failed
    }
}

/// Free the KeyHandleFFI instance.
/// # Safety
/// This function is unsafe as it requires the caller to ensure that the pointer is valid
/// and that it has not been freed previously.
#[no_mangle]
pub unsafe extern "C" fn key_handle_ffi_free(ptr: *mut KeyHandleFFI) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr); // Automatically drop and deallocate
    }
}

use super::provider::ProviderFFI;
use crate::common::factory::{SecModules, SecurityModule};
use async_std::{sync::Mutex, task::block_on};
use once_cell::sync::Lazy;
use std::{ffi::CStr, os::raw::c_char};

// Error codes
const ERROR_SUCCESS: i32 = 0;
const ERROR_NULL_POINTER: i32 = -1;
const ERROR_INVALID_UTF8: i32 = -2;
const ERROR_INSTANCE_NOT_FOUND: i32 = -3;

// Thread-safe global error message storage
static LAST_ERROR: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

/// Exposes a C-compatible interface to manage security module instances.
/// Retrieves a security module instance based on key identifier and module type.
///
/// # Safety
/// This function is unsafe because it handles raw pointers which must be valid:
/// - `key_id` and `module_type` must be valid pointers to null-terminated C strings.
/// - `out_provider` must be a valid pointer to a `*mut ProviderFFI`.
/// - The function does not check string content validity beyond proper UTF-8 encoding.
/// - It assumes that external synchronization is handled, if required.
///
/// # Parameters
/// - `key_id`: A pointer to a null-terminated C string representing the key identifier.
/// - `module_type`: A pointer to a null-terminated C string representing the type of module.
/// - `out_provider`: A pointer to a `*mut ProviderFFI` where the new instance will be stored.
///
/// # Returns
/// An integer representing the result of the operation:
/// - 0: Success
/// - -1: Null pointer error
/// - -2: Invalid UTF-8 error
/// - -3: Instance not found error
#[no_mangle]
pub unsafe extern "C" fn secmodules_get_instance(
    key_id: *const c_char,
    module_type: *const c_char,
    out_provider: *mut *mut ProviderFFI,
) -> i32 {
    if key_id.is_null() || module_type.is_null() || out_provider.is_null() {
        set_last_error("Null pointer provided".to_string());
        return ERROR_NULL_POINTER;
    }

    let key_id_str = match CStr::from_ptr(key_id).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in key_id".to_string());
            return ERROR_INVALID_UTF8;
        }
    };

    let module_type_str = match CStr::from_ptr(module_type).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in module_type".to_string());
            return ERROR_INVALID_UTF8;
        }
    };

    let module = SecurityModule::from(module_type_str);

    let result = block_on(SecModules::get_instance(
        key_id_str.to_string(),
        module,
        None,
    ));

    match result {
        Some(provider) => {
            let provider_ffi = ProviderFFI::new(provider);
            *out_provider = provider_ffi;
            ERROR_SUCCESS
        }
        None => {
            set_last_error("Failed to get instance".to_string());
            ERROR_INSTANCE_NOT_FOUND
        }
    }
}

/// Sets the last error message.
fn set_last_error(error: String) {
    block_on(async {
        let mut last_error = LAST_ERROR.lock().await;
        *last_error = error;
    });
}

/// Retrieves the last error message.
///
/// # Safety
/// This function is unsafe because it writes to a raw pointer.
/// The caller must ensure that the pointer is valid and points to a buffer
/// large enough to hold the error message.
///
/// # Parameters
/// - `buffer`: A pointer to a buffer where the error message will be written.
/// - `buffer_size`: The size of the buffer.
///
/// # Returns
/// The number of bytes written to the buffer, or -1 if an error occurred.
#[no_mangle]
pub unsafe extern "C" fn secmodules_get_last_error(buffer: *mut c_char, buffer_size: usize) -> i32 {
    if buffer.is_null() {
        return -1;
    }

    block_on(async {
        let last_error = LAST_ERROR.lock().await;
        let bytes_to_copy = std::cmp::min(last_error.len(), buffer_size - 1);
        std::ptr::copy_nonoverlapping(last_error.as_ptr() as *const c_char, buffer, bytes_to_copy);
        *buffer.add(bytes_to_copy) = 0; // Null-terminate the string
        bytes_to_copy as i32
    })
}

/// Safely frees a `ProviderFFI` instance.
///
/// # Safety
/// This function is unsafe because it directly handles raw pointers:
/// - The caller must ensure that `ptr` is a valid pointer to a `ProviderFFI` instance.
/// - The caller must guarantee that the instance has not been freed already.
/// - This function will properly deallocate the instance and its associated provider,
///   handling the memory management as expected in Rust.
///
/// # Parameters
/// - `ptr`: A pointer to a `ProviderFFI` instance to be freed.
#[no_mangle]
pub unsafe extern "C" fn secmodules_free_instance(ptr: *mut ProviderFFI) {
    if !ptr.is_null() {
        unsafe {
            let boxed = Box::from_raw(ptr);
            let provider = Box::from_raw(boxed.provider);

            // Drop the Arc<Mutex<dyn Provider>>
            drop(provider);
        }
    }
}

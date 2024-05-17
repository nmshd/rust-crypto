use super::provider::ProviderFFI;
use crate::common::factory::{SecModules, SecurityModule};
use std::{ffi::CStr, os::raw::c_char, ptr};

/// Exposes a C-compatible interface to manage security module instances.
/// Retrieves a security module instance based on key identifier and module type.
///
/// # Safety
/// This function is unsafe because it handles raw pointers which must be valid:
/// - `key_id` and `module_type` must be valid pointers to null-terminated C strings.
/// - The function does not check string content validity beyond proper UTF-8 encoding.
/// - It assumes that external synchronization is handled, if required.
///
/// # Parameters
/// - `key_id`: A pointer to a null-terminated C string representing the key identifier.
/// - `module_type`: A pointer to a null-terminated C string representing the type of module.
///
/// # Returns
/// - A valid pointer to a `ProviderFFI` if successful.
/// - `ptr::null_mut()` if the instance cannot be retrieved or input pointers are null.
#[no_mangle]
pub unsafe extern "C" fn secmodules_get_instance(
    key_id: *const c_char,
    module_type: *const c_char,
) -> *mut ProviderFFI {
    if key_id.is_null() || module_type.is_null() {
        return ptr::null_mut();
    }

    let key_id_cstr = unsafe { CStr::from_ptr(key_id) };
    let module_type_cstr = unsafe { CStr::from_ptr(module_type) };

    let key_id_str = match key_id_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let module_type_str = match module_type_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };

    let module = SecurityModule::from(module_type_str);
  
    match SecModules::get_instance(key_id_str.to_string(), module, None) {
        Some(provider) => ProviderFFI::new(provider),
        None => ptr::null_mut(),
    }
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
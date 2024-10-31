use async_std::{sync::Mutex, task::block_on};

use crate::{
    common::traits::{
        key_handle::KeyHandle, module_provider::Provider, module_provider_config::ProviderConfig,
    },
    tpm::TpmConfig,
};
use std::{
    ffi::{c_void, CStr},
    os::raw::c_char,
    sync::Arc,
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
        // Synchronously lock the provider using block_on
        let mut provider_lock = block_on(provider.lock());

        Box::into_raw(Box::new(ProviderFFI {
            provider: (&mut *provider_lock) as *mut dyn Provider,
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
pub unsafe extern "C" fn initialize_module(provider_ffi: *mut ProviderFFI) -> i32 {
    let provider_ffi = &mut *provider_ffi;

    // Synchronously initialize the module using block_on
    let result = block_on((*provider_ffi.provider).initialize_module());

    match result {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "C" fn config_new() -> *mut c_void {
    let config: Box<dyn ProviderConfig> = Box::<TpmConfig>::default();
    let ptr: *mut dyn ProviderConfig = Box::into_raw(config);
    ptr as *mut c_void
}

#[no_mangle]
pub extern "C" fn config_free(config: *mut c_void) {
    assert!(!config.is_null());
    unsafe {
        // Cast the void pointer back to the original Box<dyn Config>
        let config: *mut Box<dyn ProviderConfig> = config as *mut Box<dyn ProviderConfig>;
        // Convert it back to a Box to properly drop it
        let _owned: Box<dyn ProviderConfig> = *Box::from_raw(config);
        // The Box<_owned> is dropped here, properly deallocating the memory.
    }
}

/// Creates a new cryptographic key
/// # Safety
/// The function assumes that the key_id pointer is valid and points to a valid C string.
#[no_mangle]
pub unsafe extern "C" fn create_key(
    provider_ffi: *mut ProviderFFI,
    key_id: *const c_char,
    config: *mut c_void,
) -> i32 {
    if provider_ffi.is_null() || key_id.is_null() || config.is_null() {
        return -1; // Return error if any pointer is null
    }

    let provider = &mut *provider_ffi;
    let key_id_cstr = CStr::from_ptr(key_id);

    let key_id_str = match key_id_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1, // Error handling for invalid UTF-8
    };

    // Cast the void pointer back to Box<dyn ProviderConfig>
    let config: Box<dyn ProviderConfig> = {
        // Convert it back to a Box to properly handle the ownership
        let boxed_config: Box<Box<dyn ProviderConfig>> =
            Box::from_raw(config as *mut Box<dyn ProviderConfig>);
        *boxed_config
    };

    // Synchronously handle the async create_key call
    let result = block_on((*provider.provider).create_key(key_id_str, config));

    match result {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

/// Loads an existing cryptographic key
/// # Safety
/// The function assumes that the key_id pointer is valid and points to a valid C string.
#[no_mangle]
pub unsafe extern "C" fn load_key(
    provider_ffi: *mut ProviderFFI,
    key_id: *const c_char,
    config: *mut c_void,
) -> i32 {
    if provider_ffi.is_null() || key_id.is_null() || config.is_null() {
        return -1; // Return error if any pointer is null
    }

    let provider = &mut *provider_ffi;
    let key_id_cstr = CStr::from_ptr(key_id);

    let key_id_str = match key_id_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1, // Error handling for invalid UTF-8
    };

    // Cast the void pointer back to Box<dyn ProviderConfig>
    let config: Box<dyn ProviderConfig> = {
        // Convert it back to a Box to properly handle the ownership
        let boxed_config: Box<Box<dyn ProviderConfig>> =
            Box::from_raw(config as *mut Box<dyn ProviderConfig>);
        *boxed_config
    };

    // Synchronously handle the async load_key call
    let result = block_on((*provider.provider).load_key(key_id_str, config));

    match result {
        Ok(_) => 0,
        Err(_) => 1,
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

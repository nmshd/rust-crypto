// use crate::common::traits::key_handle::KeyHandle;
// use std::sync::{Arc, Mutex};

// #[repr(C)]
// pub struct KeyHandleFFI {
//     pub key_handle: *mut dyn KeyHandle,
// }

// impl KeyHandleFFI {
//     /// Create a new KeyHandleFFI instance from a raw pointer to a KeyHandle trait object.
//     /// # Safety
//     /// The caller must ensure that the key_handle pointer is valid and that KeyHandleFFI
//     /// takes ownership of the pointer. KeyHandleFFI is responsible for the proper
//     /// deallocation of the key handle.
//     #[no_mangle]
//     pub unsafe fn new(key_handle: Arc<Mutex<dyn KeyHandle>>) -> *mut KeyHandleFFI {
//         Box::into_raw(Box::new(KeyHandleFFI {
//             key_handle: (&mut *key_handle.lock().unwrap()) as *mut dyn KeyHandle,
//         }))
//     }
// }

// /// Signs data using the cryptographic key.
// /// # Safety
// /// Assumes `key_handle_ffi` is a valid pointer to an object implementing `KeyHandle`.
// #[no_mangle]
// pub unsafe extern "C" fn key_handle_sign_data(
//     key_handle_ffi: *mut KeyHandleFFI,
//     data: *const u8,
//     data_len: usize,
//     output: *mut u8,
//     output_capacity: usize,
//     actual_output_len: *mut usize,
// ) -> i32 {
//     if key_handle_ffi.is_null() || data.is_null() || output.is_null() || actual_output_len.is_null()
//     {
//         return -1; // Error handling for null pointer
//     }

//     let key_handle = &mut *(*key_handle_ffi).key_handle;
//     let data_slice = std::slice::from_raw_parts(data, data_len);

//     match key_handle.sign_data(data_slice) {
//         Ok(signature) => {
//             if signature.len() > output_capacity {
//                 return -2; // Buffer too small
//             }
//             std::ptr::copy_nonoverlapping(signature.as_ptr(), output, signature.len());
//             *actual_output_len = signature.len();
//             0 // Success
//         }
//         Err(_) => -3, // Operation failed
//     }
// }

// /// Encrypts data using the cryptographic key.
// /// # Safety
// /// Assumes `key_handle_ffi` is a valid pointer to an object implementing `KeyHandle`.
// #[no_mangle]
// pub unsafe extern "C" fn key_handle_encrypt_data(
//     key_handle_ffi: *mut KeyHandleFFI,
//     data: *const u8,
//     data_len: usize,
//     output: *mut u8,
//     output_capacity: usize,
//     actual_output_len: *mut usize,
// ) -> i32 {
//     if key_handle_ffi.is_null() || data.is_null() || output.is_null() || actual_output_len.is_null()
//     {
//         return -1; // Error handling for null pointer
//     }

//     let key_handle = &mut *(*key_handle_ffi).key_handle;
//     let data_slice = std::slice::from_raw_parts(data, data_len);

//     match key_handle.encrypt_data(data_slice) {
//         Ok(encrypted_data) => {
//             if encrypted_data.len() > output_capacity {
//                 return -2; // Buffer too small
//             }
//             std::ptr::copy_nonoverlapping(encrypted_data.as_ptr(), output, encrypted_data.len());
//             *actual_output_len = encrypted_data.len();
//             0 // Success
//         }
//         Err(_) => -3, // Operation failed
//     }
// }

// /// Verifies the signature of given data.
// /// # Safety
// /// Assumes `key_handle_ffi` is a valid pointer to an object implementing `KeyHandle`.
// #[no_mangle]
// pub unsafe extern "C" fn key_handle_verify_signature(
//     key_handle_ffi: *mut KeyHandleFFI,
//     data: *const u8,
//     data_len: usize,
//     signature: *const u8,
//     signature_len: usize,
// ) -> i32 {
//     if key_handle_ffi.is_null() || data.is_null() || signature.is_null() {
//         return -1; // Error handling for null pointer
//     }

//     let key_handle = &mut *(*key_handle_ffi).key_handle;
//     let data_slice = std::slice::from_raw_parts(data, data_len);
//     let signature_slice = std::slice::from_raw_parts(signature, signature_len);

//     match key_handle.verify_signature(data_slice, signature_slice) {
//         Ok(valid) => {
//             if valid {
//                 0
//             } else {
//                 -3
//             }
//         } // 0 for valid, -3 for invalid signature
//         Err(_) => -2, // Operation failed
//     }
// }

// /// Free the KeyHandleFFI instance.
// /// # Safety
// /// This function is unsafe as it requires the caller to ensure that the pointer is valid
// /// and that it has not been freed previously.
// #[no_mangle]
// pub unsafe extern "C" fn key_handle_ffi_free(ptr: *mut KeyHandleFFI) {
//     if !ptr.is_null() {
//         let _ = Box::from_raw(ptr); // Automatically drop and deallocate
//     }
// }

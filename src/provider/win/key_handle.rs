use crate::{
    common::{
        traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
        DHExchange, KeyHandle,
    },
    prelude::{AsymmetricKeySpec, CalError, Cipher, CryptoHash, KeyPairSpec, KeySpec},
    provider::win::execute_ncrypt_function,
    storage::StorageManager,
};
use anyhow::anyhow;
use nanoid::nanoid;
use std::{ffi::c_void, mem, ptr};
use tracing::debug;
use windows::{
    core::{w, PCWSTR},
    Win32::{
        Foundation, Globalization,
        Security::Cryptography::{
            BCryptBuffer, BCryptBufferDesc, BCryptCloseAlgorithmProvider, BCryptCreateHash,
            BCryptDestroyHash, BCryptFinishHash, BCryptGenRandom, BCryptGetProperty,
            BCryptHashData, BCryptOpenAlgorithmProvider, NCryptDecrypt, NCryptDeleteKey,
            NCryptEncrypt, NCryptExportKey, NCryptFreeObject, NCryptImportKey, NCryptKeyDerivation,
            NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, NCryptVerifySignature,
            BCRYPT_AES_ALGORITHM, BCRYPT_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, BCRYPT_ECCPRIVATE_BLOB,
            BCRYPT_ECCPUBLIC_BLOB, BCRYPT_HASH_HANDLE, BCRYPT_HASH_LENGTH, BCRYPT_KEY_DATA_BLOB,
            BCRYPT_KEY_DATA_BLOB_HEADER, BCRYPT_KEY_DATA_BLOB_MAGIC, BCRYPT_OBJECT_LENGTH,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_PBKDF2_ALGORITHM, BCRYPT_RSAPRIVATE_BLOB,
            BCRYPT_RSAPUBLIC_BLOB, BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA384_ALGORITHM,
            BCRYPT_SHA512_ALGORITHM, BCRYPT_USE_SYSTEM_PREFERRED_RNG, KDF_ALGORITHMID,
            KDF_HASH_ALGORITHM, KDF_ITERATION_COUNT, KDF_SALT, MS_KEY_STORAGE_PROVIDER,
            NCRYPT_ALGORITHM_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_CHAINING_MODE_PROPERTY,
            NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY,
            NCRYPT_NO_PADDING_FLAG, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
        },
    },
};

use super::{crypto_hash_to_pcwstr, NcryptProvHandleWrapper};

const GCM_NONCE_SIZE_BYTES: usize = 12;
const GCM_TAG_SIZE_BYTES: usize = 16; // Standard for AES-GCM

// Wrapper for NCRYPT_KEY_HANDLE to ensure NCryptFreeObject is called on drop.
#[derive(Debug, Clone)]
pub(crate) struct NcryptKeyHandleWrapper(pub NCRYPT_KEY_HANDLE);

impl Drop for NcryptKeyHandleWrapper {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let result = unsafe { NCryptFreeObject(self.0.into()) };
            if result.is_err() {
                debug!(
                    "Failed to free NCRYPT_KEY_HANDLE {:?}: {:?}",
                    self.0, result
                );
            }
        }
    }
}

unsafe impl Send for NcryptKeyHandleWrapper {}
unsafe impl Sync for NcryptKeyHandleWrapper {}

#[derive(Debug, Clone)]
pub(crate) struct WindowsKeyHandle {
    pub(super) key_id: String,
    pub(super) key_handle: NcryptKeyHandleWrapper,
    pub(super) spec: KeySpec,
    pub(super) storage_manager: Option<StorageManager>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct WindowsKeyPairHandle {
    pub(super) key_id: String,
    pub(super) key_handle: NcryptKeyHandleWrapper,
    pub(super) spec: KeyPairSpec,
    pub(super) public_key_bytes: Option<Vec<u8>>,
    pub(super) storage_manager: Option<StorageManager>,
}

// Default iteration count for PBKDF2
const PBKDF2_DEFAULT_ITERATIONS: u64 = 100_000;

// String literal for GCM chaining mode
const NCRYPT_CHAINING_MODE_GCM_STR_VALUE: PCWSTR = w!("ChainingModeGCM");

// Helper to get CNG Chaining Mode Value (Vec<u16>) for a Cipher
fn cipher_to_cng_chaining_mode_value_vec_u16(cipher: Cipher) -> Result<Vec<u16>, CalError> {
    let pcwstr_val = match cipher {
        Cipher::AesGcm128 | Cipher::AesGcm256 => NCRYPT_CHAINING_MODE_GCM_STR_VALUE, // Corrected constant name
        // Example for other modes:
        // Cipher::AesCbc128 | Cipher::AesCbc256 => CBC_CHAINING_MODE_STR_VALUE,
        _ => {
            return Err(CalError::unsupported_algorithm(format!(
                "Cipher {cipher:?} does not have a defined CNG chaining mode string value for this implementation."
            )))
        }
    };
    Ok(pcwstr_to_vec_u16(pcwstr_val))
}

// Helper to convert PCWSTR to a null-terminated Vec<u16>
fn pcwstr_to_vec_u16(pcwstr: PCWSTR) -> Vec<u16> {
    if pcwstr.is_null() {
        return vec![0];
    }
    // SAFETY: pcwstr is a valid pointer to a null-terminated wide string if not null.
    let len = unsafe { Globalization::lstrlenW(pcwstr) } as usize;
    // SAFETY: Accessing memory pointed to by pcwstr up to 'len' characters.
    let slice = unsafe { std::slice::from_raw_parts(pcwstr.0, len) };
    let mut vec = slice.to_vec();
    vec.push(0);
    vec
}

// Helper to get CNG Algorithm Name (Vec<u16>) for a CryptoHash
fn crypto_hash_to_cng_algorithm_vec_u16(hash: CryptoHash) -> Result<Vec<u16>, CalError> {
    let pcwstr = match hash {
        CryptoHash::Sha2_256 => BCRYPT_SHA256_ALGORITHM,
        CryptoHash::Sha2_384 => BCRYPT_SHA384_ALGORITHM,
        CryptoHash::Sha2_512 => BCRYPT_SHA512_ALGORITHM,
        _ => {
            return Err(CalError::unsupported_algorithm(format!(
                "Unsupported hash algorithm for PBKDF2: {hash:?}"
            )))
        }
    };
    Ok(pcwstr_to_vec_u16(pcwstr))
}

// Helper to get CNG Algorithm Name (Vec<u16>) for a Cipher
fn cipher_to_cng_algorithm_vec_u16(cipher: Cipher) -> Result<Vec<u16>, CalError> {
    let pcwstr = match cipher {
        Cipher::AesGcm128 | Cipher::AesGcm256 => BCRYPT_AES_ALGORITHM,
        _ => {
            return Err(CalError::unsupported_algorithm(format!(
                "Unsupported cipher for CNG property: {cipher:?}"
            )))
        }
    };
    Ok(pcwstr_to_vec_u16(pcwstr))
}

fn asymmetric_spec_to_public_blob_type(spec: AsymmetricKeySpec) -> Result<PCWSTR, CalError> {
    match spec {
        AsymmetricKeySpec::RSA1024
        | AsymmetricKeySpec::RSA2048
        | AsymmetricKeySpec::RSA3072
        | AsymmetricKeySpec::RSA4096
        | AsymmetricKeySpec::RSA8192 => Ok(BCRYPT_RSAPUBLIC_BLOB),
        AsymmetricKeySpec::P256 | AsymmetricKeySpec::P384 | AsymmetricKeySpec::P521 => {
            Ok(BCRYPT_ECCPUBLIC_BLOB)
        }
        _ => Err(CalError::unsupported_algorithm(format!(
            "AsymmetricKeySpec {spec:?} does not have a public blob type for WindowsProvider"
        ))),
    }
}

fn asymmetric_spec_to_private_blob_type(spec: AsymmetricKeySpec) -> Result<PCWSTR, CalError> {
    match spec {
        AsymmetricKeySpec::RSA1024
        | AsymmetricKeySpec::RSA2048
        | AsymmetricKeySpec::RSA3072
        | AsymmetricKeySpec::RSA4096
        | AsymmetricKeySpec::RSA8192 => Ok(BCRYPT_RSAPRIVATE_BLOB),
        AsymmetricKeySpec::P256 | AsymmetricKeySpec::P384 | AsymmetricKeySpec::P521 => {
            Ok(BCRYPT_ECCPRIVATE_BLOB)
        }
        _ => Err(CalError::unsupported_algorithm(format!(
            "AsymmetricKeySpec {spec:?} does not have a private blob type for WindowsProvider"
        ))),
    }
}

impl KeyHandleImpl for WindowsKeyHandle {
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        match self.spec.cipher {
            Cipher::AesGcm128 | Cipher::AesGcm256 => {
                let nonce_bytes = if iv.is_empty() {
                    let mut buffer = vec![0u8; GCM_NONCE_SIZE_BYTES];
                    execute_ncrypt_function!(BCryptGenRandom(
                        None,
                        &mut buffer,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                    ))?;
                    buffer
                } else if iv.len() == GCM_NONCE_SIZE_BYTES {
                    iv.to_vec()
                } else {
                    return Err(CalError::bad_parameter(
                        format!(
                            "Invalid IV length for AES-GCM: expected {} bytes, got {}",
                            GCM_NONCE_SIZE_BYTES,
                            iv.len()
                        ),
                        false,
                        None,
                    ));
                };

                let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                    cbSize: mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                    ..Default::default()
                };
                auth_info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

                auth_info.pbNonce = nonce_bytes.as_ptr() as *mut u8;
                auth_info.cbNonce = nonce_bytes.len() as u32;
                // pbAuthData and cbAuthData are null/0 for empty AAD by default from BCRYPT_INIT_AUTH_MODE_INFO

                let mut tag_buffer = vec![0u8; GCM_TAG_SIZE_BYTES];
                auth_info.pbTag = tag_buffer.as_mut_ptr();
                auth_info.cbTag = tag_buffer.len() as u32;

                let mut encrypted_len: u32 = 0;
                // First call to get the required buffer size for ciphertext
                execute_ncrypt_function!(@result NCryptEncrypt(
                    self.key_handle.0,
                    Some(data),
                    Some(ptr::addr_of_mut!(auth_info) as *mut c_void),
                    None, // Output buffer
                    &mut encrypted_len,
                    NCRYPT_NO_PADDING_FLAG, // No padding for GCM
                ))?;

                let mut encrypted_buffer = vec![0u8; encrypted_len as usize];

                // Second call to perform encryption
                // auth_info.pbTag will be populated by this call
                execute_ncrypt_function!(@result NCryptEncrypt(
                    self.key_handle.0,
                    Some(data),
                    Some(ptr::addr_of_mut!(auth_info) as *mut c_void),
                    Some(&mut encrypted_buffer),
                    &mut encrypted_len,
                    NCRYPT_NO_PADDING_FLAG,
                ))?;
                encrypted_buffer.truncate(encrypted_len as usize); // Adjust to actual size

                // Concatenate ciphertext and tag
                let mut ciphertext_and_tag =
                    Vec::with_capacity(encrypted_buffer.len() + tag_buffer.len());
                ciphertext_and_tag.extend_from_slice(&encrypted_buffer);
                ciphertext_and_tag.extend_from_slice(&tag_buffer);

                Ok((ciphertext_and_tag, nonce_bytes))
            }
            _ => Err(CalError::unsupported_algorithm(format!(
                "Cipher {:?} not supported for encryption by WindowsProvider",
                self.spec.cipher
            ))),
        }
    }

    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        match self.spec.cipher {
            Cipher::AesGcm128 | Cipher::AesGcm256 => {
                if iv.len() != GCM_NONCE_SIZE_BYTES {
                    return Err(CalError::bad_parameter(
                        format!(
                            "Invalid IV length for AES-GCM decryption: expected {} bytes, got {}",
                            GCM_NONCE_SIZE_BYTES,
                            iv.len()
                        ),
                        false,
                        None,
                    ));
                }
                if encrypted_data.len() < GCM_TAG_SIZE_BYTES {
                    return Err(CalError::bad_parameter(
                        "Encrypted data is too short to contain a tag.".to_string(),
                        false,
                        None,
                    ));
                }

                let (ciphertext, tag) =
                    encrypted_data.split_at(encrypted_data.len() - GCM_TAG_SIZE_BYTES);

                let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                    cbSize: mem::size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                    ..Default::default()
                };
                auth_info.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;

                auth_info.pbNonce = iv.as_ptr() as *mut u8;
                auth_info.cbNonce = iv.len() as u32;
                auth_info.pbTag = tag.as_ptr() as *mut u8;
                auth_info.cbTag = tag.len() as u32;

                let mut decrypted_len: u32 = 0;
                // First call to get the required buffer size
                execute_ncrypt_function!(@result NCryptDecrypt(
                    self.key_handle.0,
                    Some(ciphertext),
                    Some(ptr::addr_of_mut!(auth_info) as *mut c_void),
                    None, // Output buffer
                    &mut decrypted_len,
                    NCRYPT_NO_PADDING_FLAG,
                ))?;

                let mut decrypted_buffer = vec![0u8; decrypted_len as usize];

                // Second call to perform decryption
                execute_ncrypt_function!(@result NCryptDecrypt(
                    self.key_handle.0,
                    Some(ciphertext),
                    Some(ptr::addr_of_mut!(auth_info) as *mut c_void),
                    Some(&mut decrypted_buffer),
                    &mut decrypted_len,
                    NCRYPT_NO_PADDING_FLAG,
                ))?;
                decrypted_buffer.truncate(decrypted_len as usize);

                Ok(decrypted_buffer)
            }
            _ => Err(CalError::unsupported_algorithm(format!(
                "Cipher {:?} not supported for decryption by WindowsProvider",
                self.spec.cipher
            ))),
        }
    }

    fn hmac(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("HMAC not supported for AES keys")
    }

    fn verify_hmac(&self, _data: &[u8], _hmac_to_verify: &[u8]) -> Result<bool, CalError> {
        todo!("HMAC not supported for AES keys")
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        let blob_type = BCRYPT_KEY_DATA_BLOB;
        let mut exported_key_len: u32 = 0;

        // First call to get length
        execute_ncrypt_function!(@result NCryptExportKey(
            self.key_handle.0,
            Some(NCRYPT_KEY_HANDLE::default()), // No wrapping key
            blob_type,
            None, // No parameter list
            None, // Output buffer
            &mut exported_key_len,
            NCRYPT_SILENT_FLAG,
        ))?;

        let mut exported_key_blob = vec![0u8; exported_key_len as usize];

        // Second call to export key
        execute_ncrypt_function!(@result NCryptExportKey(
            self.key_handle.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            blob_type,
            None,
            Some(&mut exported_key_blob),
            &mut exported_key_len,
            NCRYPT_SILENT_FLAG,
        ))?;
        exported_key_blob.truncate(exported_key_len as usize);

        // Parse BCRYPT_KEY_DATA_BLOB_HEADER
        if exported_key_blob.len() < size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>() {
            return Err(CalError::failed_operation(
                "Exported key data blob is too small for header.".to_string(),
                true,
                None,
            ));
        }

        let header = unsafe { *(exported_key_blob.as_ptr() as *const BCRYPT_KEY_DATA_BLOB_HEADER) };

        if header.dwMagic != BCRYPT_KEY_DATA_BLOB_MAGIC {
            return Err(CalError::failed_operation(
                "Invalid magic number in exported key data blob.".to_string(),
                true,
                None,
            ));
        }

        let key_offset = size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>();
        if exported_key_blob.len() < key_offset + header.cbKeyData as usize {
            return Err(CalError::failed_operation(
                "Exported key data blob is smaller than indicated by header.".to_string(),
                true,
                None,
            ));
        }

        let raw_key =
            exported_key_blob[key_offset..(key_offset + header.cbKeyData as usize)].to_vec();
        Ok(raw_key)
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    fn delete(self) -> Result<(), CalError> {
        if !self.spec.ephemeral {
            // For persisted keys, NCryptDeleteKey removes it from the KSP.
            // The NCRYPT_SILENT_FLAG can be used if no UI is desired.
            // The key handle self.key_handle.0 must be valid.
            execute_ncrypt_function!(@result NCryptDeleteKey(self.key_handle.0, NCRYPT_SILENT_FLAG.0))?;
        }
        // The key handle itself (self.key_handle) will be freed by its Drop impl (NcryptKeyHandleWrapper)
        // If self.storage_manager was used for CAL-specific metadata, delete here:
        if let Some(sm) = self.storage_manager {
            sm.delete(self.key_id)?
        }
        Ok(())
    }

    fn spec(&self) -> KeySpec {
        self.spec
    }

    fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError> {
        let mut new_spec = self.spec();
        new_spec.ephemeral = true;
        let key_length_bytes = new_spec.cipher.len();
        let derived_key_id_str = nanoid!(10);

        // --- 1. Prepare parameters for NCryptKeyDerivation ---
        let mut pbkdf2_alg_id_wide = pcwstr_to_vec_u16(BCRYPT_PBKDF2_ALGORITHM);
        let mut kdf_hash_alg_wide = crypto_hash_to_cng_algorithm_vec_u16(new_spec.signing_hash)?;
        let mut iteration_count_val: u64 = PBKDF2_DEFAULT_ITERATIONS;
        let salt_ptr = nonce.as_ptr() as *mut c_void; // KDF_SALT is PVOID

        let mut buffers: Vec<BCryptBuffer> = vec![
            BCryptBuffer {
                cbBuffer: (pbkdf2_alg_id_wide.len() * mem::size_of::<u16>()) as u32,
                BufferType: KDF_ALGORITHMID,
                pvBuffer: pbkdf2_alg_id_wide.as_mut_ptr() as *mut c_void,
            },
            BCryptBuffer {
                cbBuffer: (kdf_hash_alg_wide.len() * mem::size_of::<u16>()) as u32,
                BufferType: KDF_HASH_ALGORITHM,
                pvBuffer: kdf_hash_alg_wide.as_mut_ptr() as *mut c_void,
            },
            BCryptBuffer {
                cbBuffer: mem::size_of::<u64>() as u32,
                BufferType: KDF_ITERATION_COUNT,
                pvBuffer: &mut iteration_count_val as *mut u64 as *mut c_void,
            },
            BCryptBuffer {
                cbBuffer: nonce.len() as u32,
                BufferType: KDF_SALT,
                pvBuffer: salt_ptr,
            },
        ];
        let parameter_list = BCryptBufferDesc {
            ulVersion: 0,
            cBuffers: buffers.len() as u32,
            pBuffers: buffers.as_mut_ptr(),
        };

        // --- 2. Perform NCryptKeyDerivation ---
        // First call: Query for derived key length
        let mut derived_key_len_result: u32 = 0;
        let mut empty_buffer_for_len_query: [u8; 0] = []; // Empty slice for length query

        // Use execute_ncrypt_function! for the call
        execute_ncrypt_function!(@result NCryptKeyDerivation(
            self.key_handle.0,                      // hKey
            Some(&parameter_list),                  // pParameterList
            &mut empty_buffer_for_len_query,        // pbDerivedKey (empty slice for length query)
            &mut derived_key_len_result,            // pcbResult
            0,                                      // dwFlags
        ))?;

        if derived_key_len_result != key_length_bytes as u32 {
            return Err(CalError::failed_operation(
                format!(
                    "NCryptKeyDerivation derived key length mismatch. Expected: {key_length_bytes}, Got: {derived_key_len_result}"
                ),
                true,
                None,
            ));
        }

        // Second call: Derive the key
        let mut derived_raw_key_bytes = vec![0u8; derived_key_len_result as usize];
        let mut bytes_written: u32 = 0; // To receive the number of bytes written

        execute_ncrypt_function!(@result NCryptKeyDerivation(
            self.key_handle.0,                      // hKey
            Some(&parameter_list),                  // pParameterList
            &mut derived_raw_key_bytes,             // pbDerivedKey (actual buffer)
            &mut bytes_written,                     // pcbResult
            0,                                      // dwFlags
        ))?;

        if bytes_written != derived_key_len_result {
            return Err(CalError::failed_operation(
                format!(
                    "NCryptKeyDerivation bytes written mismatch. Expected: {derived_key_len_result}, Got: {bytes_written}"
                ),
                true,
                None,
            ));
        }

        // --- 3. Import derived raw key bytes into CNG ---
        let mut h_prov_val: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE::default();
        execute_ncrypt_function!(@result NCryptOpenStorageProvider(
            &mut h_prov_val,
            MS_KEY_STORAGE_PROVIDER,
            0
        ))?;
        let h_prov = NcryptProvHandleWrapper(h_prov_val);

        let key_blob_header = BCRYPT_KEY_DATA_BLOB_HEADER {
            dwMagic: BCRYPT_KEY_DATA_BLOB_MAGIC,
            dwVersion: 1,
            cbKeyData: derived_raw_key_bytes.len() as u32,
        };
        let mut key_data_blob: Vec<u8> = Vec::with_capacity(
            size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>() + derived_raw_key_bytes.len(),
        );
        key_data_blob.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &key_blob_header as *const _ as *const u8,
                size_of::<BCRYPT_KEY_DATA_BLOB_HEADER>(),
            )
        });
        key_data_blob.extend_from_slice(&derived_raw_key_bytes);

        let mut h_derived_key_val: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE::default();
        execute_ncrypt_function!(@result NCryptImportKey(
            h_prov.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            BCRYPT_KEY_DATA_BLOB,
            None, // pParameterList
            &mut h_derived_key_val,
            &key_data_blob,
            NCRYPT_FLAGS(0),
        ))?;
        let h_derived_key_wrapper = NcryptKeyHandleWrapper(h_derived_key_val);

        // --- 4. Set properties on the new key handle ---
        let cng_alg_name_vec_u16 = cipher_to_cng_algorithm_vec_u16(new_spec.cipher)?;
        // NCryptSetProperty expects a &[u8] slice for pbInput.
        let cng_alg_name_bytes_view: &[u8] = unsafe {
            std::slice::from_raw_parts(
                cng_alg_name_vec_u16.as_ptr() as *const u8,
                cng_alg_name_vec_u16.len() * mem::size_of::<u16>(),
            )
        };
        execute_ncrypt_function!(@result NCryptSetProperty(
            h_derived_key_wrapper.0.into(),
            NCRYPT_ALGORITHM_PROPERTY,
            cng_alg_name_bytes_view, // pbInput
            NCRYPT_SILENT_FLAG,      // dwFlags
        ))?;

        let key_len_bits = (key_length_bytes * 8) as u32;
        let key_len_bytes_view = &key_len_bits.to_le_bytes();
        execute_ncrypt_function!(@result NCryptSetProperty(
            h_derived_key_wrapper.0.into(),
            NCRYPT_LENGTH_PROPERTY,
            key_len_bytes_view,
            NCRYPT_SILENT_FLAG,
        ))?;

        let key_usage_flags_val: u32 = NCRYPT_ALLOW_DECRYPT_FLAG;
        let key_usage_bytes_view = &key_usage_flags_val.to_le_bytes();
        execute_ncrypt_function!(@result NCryptSetProperty(
            h_derived_key_wrapper.0.into(),
            NCRYPT_KEY_USAGE_PROPERTY,
            key_usage_bytes_view,
            NCRYPT_SILENT_FLAG,
        ))?;

        if new_spec.cipher == Cipher::AesGcm128 || new_spec.cipher == Cipher::AesGcm256 {
            let cng_chain_mode_val_vec_u16 =
                cipher_to_cng_chaining_mode_value_vec_u16(new_spec.cipher)?;
            let cng_chain_mode_val_bytes_view: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    cng_chain_mode_val_vec_u16.as_ptr() as *const u8,
                    cng_chain_mode_val_vec_u16.len() * mem::size_of::<u16>(),
                )
            };
            execute_ncrypt_function!(@result NCryptSetProperty(
                h_derived_key_wrapper.0.into(),
                NCRYPT_CHAINING_MODE_PROPERTY,
                cng_chain_mode_val_bytes_view,
                NCRYPT_SILENT_FLAG,
            ))?;
        }

        // --- 5. Construct and return WindowsKeyHandle ---
        let new_windows_key_handle = WindowsKeyHandle {
            key_id: derived_key_id_str,
            key_handle: h_derived_key_wrapper,
            spec: new_spec,
            storage_manager: None,
        };

        Ok(KeyHandle {
            implementation: new_windows_key_handle.into(),
        })
    }
}

impl KeyPairHandleImpl for WindowsKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        // 1. Hash the data
        let hash_alg_id = crypto_hash_to_pcwstr(self.spec.signing_hash)?;
        let mut bcrypt_alg_handle = BCRYPT_ALG_HANDLE::default();
        let mut bcrypt_hash_handle = BCRYPT_HASH_HANDLE::default();
        let mut hash_value: Vec<u8> = vec![]; // To store the final hash

        execute_ncrypt_function!(BCryptOpenAlgorithmProvider(
            &mut bcrypt_alg_handle,
            hash_alg_id,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        ))?;

        let hashed_data_result = (|| {
            let mut object_len_value: u32 = 0;
            let mut bytes_copied_object_len: u32 = 0;
            let object_len_buffer: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut object_len_value as *mut u32 as *mut u8,
                    size_of::<u32>(),
                )
            };
            execute_ncrypt_function!(BCryptGetProperty(
                bcrypt_alg_handle.into(),
                BCRYPT_OBJECT_LENGTH,
                Some(object_len_buffer),
                &mut bytes_copied_object_len,
                0,
            ))?;
            if bytes_copied_object_len != size_of::<u32>() as u32 {
                return Err(CalError::failed_operation(
                    "BCryptGetProperty for BCRYPT_OBJECT_LENGTH returned unexpected size."
                        .to_string(),
                    true,
                    None,
                ));
            }
            let mut hash_object = vec![0u8; object_len_value as usize];

            let mut hash_len_value: u32 = 0;
            let mut bytes_copied_hash_len: u32 = 0;
            let hash_len_buffer: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut hash_len_value as *mut u32 as *mut u8,
                    size_of::<u32>(),
                )
            };
            execute_ncrypt_function!(BCryptGetProperty(
                bcrypt_alg_handle.into(),
                BCRYPT_HASH_LENGTH,
                Some(hash_len_buffer),
                &mut bytes_copied_hash_len,
                0,
            ))?;
            if bytes_copied_hash_len != size_of::<u32>() as u32 {
                return Err(CalError::failed_operation(
                    "BCryptGetProperty for BCRYPT_HASH_LENGTH returned unexpected size."
                        .to_string(),
                    true,
                    None,
                ));
            }
            hash_value = vec![0u8; hash_len_value as usize];

            execute_ncrypt_function!(BCryptCreateHash(
                bcrypt_alg_handle,
                &mut bcrypt_hash_handle,
                Some(&mut hash_object),
                None,
                0,
            ))?;
            execute_ncrypt_function!(BCryptHashData(bcrypt_hash_handle, data, 0))?;
            execute_ncrypt_function!(BCryptFinishHash(bcrypt_hash_handle, &mut hash_value, 0))?;
            Ok(hash_value.clone())
        })();

        // Cleanup BCrypt handles
        if !bcrypt_hash_handle.is_invalid() {
            let _ = unsafe { BCryptDestroyHash(bcrypt_hash_handle) };
        }
        if !bcrypt_alg_handle.is_invalid() {
            let _ = unsafe { BCryptCloseAlgorithmProvider(bcrypt_alg_handle, 0) };
        }
        let hash_to_sign = hashed_data_result?;

        // 2. Sign the hash
        let padding_flags = match self.spec.asym_spec {
            AsymmetricKeySpec::RSA1024
            | AsymmetricKeySpec::RSA2048
            | AsymmetricKeySpec::RSA3072
            | AsymmetricKeySpec::RSA4096
            | AsymmetricKeySpec::RSA8192 => NCRYPT_PAD_PKCS1_FLAG,
            _ => NCRYPT_FLAGS(0),
        };

        let mut signature_len: u32 = 0;
        execute_ncrypt_function!(@result NCryptSignHash(
            self.key_handle.0,
            None, // pPaddingInfo: No complex padding for now
            &hash_to_sign,
            None,
            &mut signature_len,
            padding_flags,
        ))?;

        let mut signature = vec![0u8; signature_len as usize];
        execute_ncrypt_function!(@result NCryptSignHash(
            self.key_handle.0,
            None,
            &hash_to_sign,
            Some(&mut signature),
            &mut signature_len,
            padding_flags,
        ))?;
        signature.truncate(signature_len as usize);

        Ok(signature)
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        // 1. Hash the data (same as in sign_data)
        let hash_alg_id = crypto_hash_to_pcwstr(self.spec.signing_hash)?;
        let mut bcrypt_alg_handle = BCRYPT_ALG_HANDLE::default();
        let mut bcrypt_hash_handle = BCRYPT_HASH_HANDLE::default();
        let mut hash_value: Vec<u8> = vec![];

        execute_ncrypt_function!(BCryptOpenAlgorithmProvider(
            &mut bcrypt_alg_handle,
            hash_alg_id,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        ))?;

        let hashed_data_result = (|| {
            let mut object_len_value: u32 = 0;
            let mut bytes_copied_object_len: u32 = 0;
            let object_len_buffer: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut object_len_value as *mut u32 as *mut u8,
                    size_of::<u32>(),
                )
            };
            execute_ncrypt_function!(BCryptGetProperty(
                bcrypt_alg_handle.into(),
                BCRYPT_OBJECT_LENGTH,
                Some(object_len_buffer),
                &mut bytes_copied_object_len,
                0,
            ))?;
            if bytes_copied_object_len != size_of::<u32>() as u32 {
                return Err(CalError::failed_operation(
                    "BCryptGetProperty for BCRYPT_OBJECT_LENGTH returned unexpected size."
                        .to_string(),
                    true,
                    None,
                ));
            }
            let mut hash_object = vec![0u8; object_len_value as usize];

            let mut hash_len_value: u32 = 0;
            let mut bytes_copied_hash_len: u32 = 0;
            let hash_len_buffer: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut hash_len_value as *mut u32 as *mut u8,
                    size_of::<u32>(),
                )
            };
            execute_ncrypt_function!(BCryptGetProperty(
                bcrypt_alg_handle.into(),
                BCRYPT_HASH_LENGTH,
                Some(hash_len_buffer),
                &mut bytes_copied_hash_len,
                0,
            ))?;
            if bytes_copied_hash_len != size_of::<u32>() as u32 {
                return Err(CalError::failed_operation(
                    "BCryptGetProperty for BCRYPT_HASH_LENGTH returned unexpected size."
                        .to_string(),
                    true,
                    None,
                ));
            }
            hash_value = vec![0u8; hash_len_value as usize];

            execute_ncrypt_function!(BCryptCreateHash(
                bcrypt_alg_handle,
                &mut bcrypt_hash_handle,
                Some(&mut hash_object),
                None,
                0,
            ))?;
            execute_ncrypt_function!(BCryptHashData(bcrypt_hash_handle, data, 0))?;
            execute_ncrypt_function!(BCryptFinishHash(bcrypt_hash_handle, &mut hash_value, 0))?;
            Ok(hash_value.clone())
        })();

        if !bcrypt_hash_handle.is_invalid() {
            let _ = unsafe { BCryptDestroyHash(bcrypt_hash_handle) };
        }
        if !bcrypt_alg_handle.is_invalid() {
            let _ = unsafe { BCryptCloseAlgorithmProvider(bcrypt_alg_handle, 0) };
        }
        let hash_to_verify = hashed_data_result?;

        // 2. Verify the signature
        let padding_flags = match self.spec.asym_spec {
            AsymmetricKeySpec::RSA1024
            | AsymmetricKeySpec::RSA2048
            | AsymmetricKeySpec::RSA3072
            | AsymmetricKeySpec::RSA4096
            | AsymmetricKeySpec::RSA8192 => NCRYPT_PAD_PKCS1_FLAG,
            _ => NCRYPT_FLAGS(0),
        };

        let verification_result = unsafe {
            NCryptVerifySignature(
                self.key_handle.0,
                None, // pPaddingInfo
                &hash_to_verify,
                signature,
                padding_flags,
            )
        };

        match verification_result {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.code() == Foundation::NTE_BAD_SIGNATURE {
                    Ok(false)
                } else {
                    Err(CalError::failed_operation(
                        format!("Windows API call NCryptVerifySignature failed: {e}"),
                        true,
                        Some(anyhow!(e)),
                    ))
                }
            }
        }
    }

    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Decryption not supported for ECC keys")
    }

    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Decryption not supported for ECC keys")
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        let blob_type = asymmetric_spec_to_public_blob_type(self.spec.asym_spec)?;
        let mut public_key_len: u32 = 0;

        execute_ncrypt_function!(@result NCryptExportKey(
            self.key_handle.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            blob_type,
            None,
            None,
            &mut public_key_len,
            NCRYPT_FLAGS(0),
        ))?;

        let mut public_key_bytes = vec![0u8; public_key_len as usize];
        execute_ncrypt_function!(@result NCryptExportKey(
            self.key_handle.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            blob_type,
            None,
            Some(&mut public_key_bytes),
            &mut public_key_len,
            NCRYPT_FLAGS(0),
        ))?;
        public_key_bytes.truncate(public_key_len as usize);
        Ok(public_key_bytes)
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        if self.spec.non_exportable {
            return Err(CalError::failed_operation(
                "Key is marked as non-exportable by spec.".to_string(),
                true,
                None,
            ));
        }

        let blob_type = asymmetric_spec_to_private_blob_type(self.spec.asym_spec)?;
        let mut private_key_len: u32 = 0;

        execute_ncrypt_function!(@result NCryptExportKey(
            self.key_handle.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            blob_type,
            None,
            None,
            &mut private_key_len,
            NCRYPT_SILENT_FLAG,
        ))?;

        let mut private_key_bytes = vec![0u8; private_key_len as usize];
        execute_ncrypt_function!(@result NCryptExportKey(
            self.key_handle.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            blob_type,
            None,
            Some(&mut private_key_bytes),
            &mut private_key_len,
            NCRYPT_SILENT_FLAG,
        ))?;
        private_key_bytes.truncate(private_key_len as usize);
        Ok(private_key_bytes)
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    fn delete(self) -> Result<(), CalError> {
        if !self.spec.ephemeral {
            execute_ncrypt_function!(@result NCryptDeleteKey(
                self.key_handle.0,
                NCRYPT_SILENT_FLAG.0
            ))?;
        }

        if let Some(sm) = self.storage_manager {
            sm.delete(self.key_id)?
        }
        Ok(())
    }

    fn spec(&self) -> KeyPairSpec {
        self.spec
    }
}

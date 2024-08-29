use super::TpmProvider;
use crate::{
    common::{error::SecurityModuleError, traits::key_handle::KeyHandle},
    tpm::core::error::TpmError,
    tpm::win::execute_ncrypt_function,
};
use async_trait::async_trait;
use std::ptr::null_mut;
use tracing::instrument;
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{
        BCryptBufferDesc, BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash,
        BCryptDestroyKey, BCryptExportKey, BCryptFinalizeKeyPair, BCryptFinishHash,
        BCryptGenerateKeyPair, BCryptGetProperty, BCryptHashData, BCryptImportKey,
        BCryptKeyDerivation, BCryptOpenAlgorithmProvider, NCryptDecrypt, NCryptEncrypt,
        NCryptExportKey, NCryptSignHash, NCryptVerifySignature, BCRYPTBUFFER_VERSION,
        BCRYPT_ALG_HANDLE, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB, BCRYPT_HASH_HANDLE,
        BCRYPT_HASH_LENGTH, BCRYPT_KEY_HANDLE, BCRYPT_KEY_LENGTH, BCRYPT_OBJECT_LENGTH,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE,
        NCRYPT_OPAQUETRANSPORT_BLOB, NCRYPT_PAD_PKCS1_FLAG, NCRYPT_SILENT_FLAG,
    },
};

/// Provides cryptographic operations for asymmetric keys on Windows,
/// such as signing, encryption, decryption, and signature verification.
#[async_trait]
impl KeyHandle for TpmProvider {
    /// Signs data using the cryptographic key.
    ///
    /// This method hashes the input data using SHA-256 and then signs the hash.
    /// It leverages the NCryptSignHash function from the Windows CNG API.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be signed.
    ///
    /// # Returns
    ///
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        // Open an algorithm provider for SHA-512
        let mut alg_handle: BCRYPT_ALG_HANDLE = self.hash.unwrap().into();
        let hash_algo: PCWSTR = self.hash.unwrap().into();

        if unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                hash_algo,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Get the size of the hash object
        let mut hash_object_size: u32 = 0;
        if unsafe {
            BCryptGetProperty(
                alg_handle,
                BCRYPT_OBJECT_LENGTH,
                None,
                &mut hash_object_size,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut hash_object = Vec::with_capacity(hash_object_size as usize);

        // Get the length of the hash
        let mut hash_length: u32 = 0;
        if unsafe { BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, None, &mut hash_length, 0) }
            .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut hash_handle = BCRYPT_HASH_HANDLE::default();
        if unsafe {
            BCryptCreateHash(
                alg_handle,
                &mut hash_handle,
                Some(hash_object.as_mut_slice()), // Pass the hash object buffer
                None,
                0, // Flags
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Hash the data
        if unsafe { BCryptHashData(hash_handle, data, 0) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Finalize the hash
        let mut hash = Vec::with_capacity(hash_length as usize);
        if unsafe { BCryptFinishHash(hash_handle, &mut hash, 0) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Determine the size of the signature
        let mut signature_size: u32 = 0;
        execute_ncrypt_function!(NCryptSignHash(
            self.key_handle.as_ref(),
            None,                  // No padding info
            &hash,                 // Hash as a slice
            None,                  // No signature buffer yet
            &mut signature_size,   // Pointer to receive the size of the signature
            NCRYPT_PAD_PKCS1_FLAG, // Padding flag
        ));

        // Allocate a buffer for the signature
        let mut signature = Vec::with_capacity(signature_size as usize);

        // Sign the hash
        execute_ncrypt_function!(NCryptSignHash(
            self.key_handle.as_ref(),
            None,                  // No padding info
            &hash,                 // Hash as a slice
            Some(&mut signature),  // Signature buffer as a mutable slice
            &mut signature_size,   // Pointer to receive the actual size of the signature
            NCRYPT_PAD_PKCS1_FLAG, // Padding flag
        ));

        // Resize the signature buffer to the actual size
        signature.truncate(signature_size as usize);

        Ok(signature)
    }

    /// Decrypts data encrypted with the corresponding public key.
    ///
    /// Utilizes the NCryptDecrypt function from the Windows CNG API.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - The data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    async fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let mut decrypted_data_len: u32 = 0;

        // First, determine the size of the decrypted data without actually decrypting
        execute_ncrypt_function!(NCryptDecrypt(
            self.key_handle.as_ref(),
            Some(encrypted_data),    // Pass encrypted data as an Option<&[u8]>
            None, // Padding information as Option<*const c_void>, adjust based on your encryption scheme
            None, // Initially, no output buffer to get the required size
            &mut decrypted_data_len, // Receives the required size of the output buffer
            NCRYPT_FLAGS(0), // Flags, adjust as necessary
        ));

        // Allocate a buffer for the decrypted data
        let mut decrypted_data = vec![0u8; decrypted_data_len as usize];

        // Perform the actual decryption
        execute_ncrypt_function!(NCryptDecrypt(
            self.key_handle.as_ref(),
            Some(encrypted_data), // Again, pass encrypted data as an Option<&[u8]>
            None, // Padding information as Option<*const c_void>, adjust based on your encryption scheme
            Some(&mut decrypted_data), // Now provide the output buffer
            &mut decrypted_data_len, // Receives the size of the decrypted data
            NCRYPT_FLAGS(0), // Flags, adjust as necessary
        ));

        // Resize the buffer to match the actual decrypted data length
        decrypted_data.resize(decrypted_data_len as usize, 0);

        Ok(decrypted_data)
    }

    /// Encrypts data with the cryptographic key.
    ///
    /// Uses the NCryptEncrypt function from the Windows CNG API.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        // First call to determine the size of the encrypted data
        let mut encrypted_data_len: u32 = 0;
        execute_ncrypt_function!(NCryptEncrypt(
            self.key_handle.as_ref(),
            Some(data),              // Input data as a slice
            None,                    // Padding information, adjust based on your encryption scheme
            None,                    // Initially, no output buffer to get the required size
            &mut encrypted_data_len, // Receive the required size of the output buffer
            NCRYPT_FLAGS(0),         // Flags, adjust as necessary
        ));

        // Allocate a buffer for the encrypted data
        let mut encrypted_data = vec![0u8; encrypted_data_len as usize];

        // Actual call to encrypt the data
        execute_ncrypt_function!(NCryptEncrypt(
            self.key_handle.as_ref(),
            Some(data),                // Input data as a slice
            None, // Padding information, adjust based on your encryption scheme
            Some(&mut encrypted_data), // Provide the output buffer
            &mut encrypted_data_len, // Receives the size of the encrypted data
            NCRYPT_FLAGS(0), // Flags, adjust as necessary
        ));

        // Resize the buffer to match the actual encrypted data length
        encrypted_data.resize(encrypted_data_len as usize, 0);

        Ok(encrypted_data)
    }

    /// Verifies a signature against the provided data.
    ///
    /// This method hashes the input data using SHA-256 and then verifies the signature.
    /// It relies on the NCryptVerifySignature function from the Windows CNG API.
    ///
    /// # Arguments
    ///
    /// * `data` - The original data associated with the signature.
    /// * `signature` - The signature to be verified.
    ///
    /// # Returns
    ///
    /// A `Result` indicating whether the signature is valid (`true`) or not (`false`),
    /// or a `SecurityModuleError` on failure.
    #[instrument]
    async fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        let mut alg_handle: BCRYPT_ALG_HANDLE = self.hash.unwrap().into();
        let alg_id: PCWSTR = self.hash.unwrap().into();

        if unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                alg_id,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Get the size of the hash object and hash length, just like in sign_data
        let mut hash_object_size: u32 = 0;
        if unsafe {
            BCryptGetProperty(
                alg_handle,
                BCRYPT_OBJECT_LENGTH,
                None,
                &mut hash_object_size,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut hash_handle = BCRYPT_HASH_HANDLE::default();
        let mut hash_object = Vec::with_capacity(hash_object_size as usize);
        let mut hash_length: u32 = 0;

        if unsafe { BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, None, &mut hash_length, 0) }
            .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        };

        if unsafe {
            BCryptCreateHash(
                alg_handle,
                &mut hash_handle,
                Some(hash_object.as_mut_slice()),
                None,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Hash the data
        if unsafe { BCryptHashData(hash_handle, data, 0) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Finalize the hash
        let mut hash = Vec::with_capacity(hash_length as usize);
        if unsafe { BCryptFinishHash(hash_handle, &mut hash, 0) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Verify the signature
        let status = unsafe {
            NCryptVerifySignature(
                self.key_handle.as_ref(),
                None, // No padding info
                hash.as_slice(),
                signature,
                NCRYPT_PAD_PKCS1_FLAG,
            )
        };

        // Cleanup
        if unsafe { BCryptDestroyHash(hash_handle) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        };
        if unsafe { BCryptCloseAlgorithmProvider(alg_handle, 0) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        };

        // Check if the signature is valid
        match status {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn derive_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        // Open an algorithm provider for SHA-256, just like in sign_data
        let mut alg_handle: BCRYPT_ALG_HANDLE = self.hash.unwrap().into();
        let alg_id: PCWSTR = self.hash.unwrap().into();

        if unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                alg_id,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut key_blob_len: u32 = 0;

        // Determine the size of the buffer needed for the key blob
        execute_ncrypt_function!(NCryptExportKey(
            *self.key_handle.as_ref().unwrap(),
            NCRYPT_KEY_HANDLE::default(),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            None,
            &mut key_blob_len,
            NCRYPT_SILENT_FLAG,
        ));

        // Allocate buffer for the key blob
        let mut key_blob = vec![0u8; key_blob_len as usize];

        // Export the key blob
        execute_ncrypt_function!(NCryptExportKey(
            self.key_handle.as_ref(),
            NCRYPT_KEY_HANDLE::default(),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut key_blob),
            &mut key_blob_len,
            NCRYPT_SILENT_FLAG,
        ));

        let mut bcrypt_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE(null_mut());

        // Import the key blob into the BCrypt layer
        if unsafe {
            BCryptImportKey(
                alg_handle,
                BCRYPT_KEY_HANDLE::default(),
                NCRYPT_OPAQUETRANSPORT_BLOB,
                &mut bcrypt_key,
                None,
                &key_blob,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let derived_key_len = self.get_key_length(alg_handle)?;

        // Allocate buffer for the derived key
        let mut derived_key = vec![0u8; derived_key_len as usize];
        let mut result_len: u32 = 0;

        // Key derivation parameters
        let parameter_list = BCryptBufferDesc {
            ulVersion: BCRYPTBUFFER_VERSION,
            cBuffers: 0,
            pBuffers: null_mut(),
        };

        // Derive the key
        if unsafe {
            BCryptKeyDerivation(
                bcrypt_key,
                Some(&parameter_list),
                &mut derived_key,
                &mut result_len,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        Ok(derived_key)
    }

    #[doc = " TODO: Docs"]
    #[doc = " # Returns"]
    #[doc = " A `Result` containing the new keypair on success or a `SecurityModuleError` on failure."]
    async fn generate_exchange_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), SecurityModuleError> {
        // Open an algorithm provider for SHA-256, just like in sign_data
        let mut alg_handle: BCRYPT_ALG_HANDLE = self.hash.unwrap().into();
        let alg_id: PCWSTR = self.hash.unwrap().into();

        if unsafe {
            BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                alg_id,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut key_blob_len: u32 = 0;

        // Determine the size of the buffer needed for the key blob
        execute_ncrypt_function!(NCryptExportKey(
            *self.key_handle.as_ref().unwrap(),
            NCRYPT_KEY_HANDLE::default(),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            None,
            &mut key_blob_len,
            NCRYPT_SILENT_FLAG,
        ));

        // Allocate buffer for the key blob
        let mut key_blob = vec![0u8; key_blob_len as usize];

        // Export the key blob
        execute_ncrypt_function!(NCryptExportKey(
            self.key_handle.as_ref(),
            NCRYPT_KEY_HANDLE::default(),
            NCRYPT_OPAQUETRANSPORT_BLOB,
            None,
            Some(&mut key_blob),
            &mut key_blob_len,
            NCRYPT_SILENT_FLAG,
        ));

        let mut bcrypt_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE(null_mut());

        // Import the key blob into the BCrypt layer
        if unsafe {
            BCryptImportKey(
                alg_handle,
                BCRYPT_KEY_HANDLE::default(),
                NCRYPT_OPAQUETRANSPORT_BLOB,
                &mut bcrypt_key,
                None,
                &key_blob,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let alg_handle: BCRYPT_ALG_HANDLE = self.hash.unwrap().into();

        // Generate an ephemeral ECDH key pair
        let mut ephemeral_key: BCRYPT_KEY_HANDLE = BCRYPT_KEY_HANDLE(null_mut());
        if unsafe {
            BCryptGenerateKeyPair(
                alg_handle,
                &mut ephemeral_key,
                256, // Key length for P-256
                0,
            )
        }
        .is_err()
        {
            let _ = unsafe { BCryptDestroyKey(bcrypt_key) };
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        if unsafe { BCryptFinalizeKeyPair(ephemeral_key, 0) }.is_err() {
            unsafe {
                let _ = BCryptDestroyKey(ephemeral_key);
                let _ = BCryptDestroyKey(bcrypt_key);
            };
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Export the public key
        let mut pub_key_size: u32 = 0;
        if unsafe {
            BCryptExportKey(
                ephemeral_key,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                &mut pub_key_size,
                0,
            )
        }
        .is_err()
        {
            unsafe {
                let _ = BCryptDestroyKey(ephemeral_key);
                let _ = BCryptDestroyKey(bcrypt_key);
            };
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut pub_key = vec![0u8; pub_key_size as usize];
        if unsafe {
            BCryptExportKey(
                ephemeral_key,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                Some(&mut pub_key),
                &mut pub_key_size,
                0,
            )
        }
        .is_err()
        {
            unsafe {
                let _ = BCryptDestroyKey(ephemeral_key);
                let _ = BCryptDestroyKey(bcrypt_key);
            };
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Export the private key
        let mut priv_key_size: u32 = 0;
        if unsafe {
            BCryptExportKey(
                ephemeral_key,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPRIVATE_BLOB,
                None,
                &mut priv_key_size,
                0,
            )
        }
        .is_err()
        {
            unsafe {
                let _ = BCryptDestroyKey(ephemeral_key);
                let _ = BCryptDestroyKey(bcrypt_key);
            };
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let mut priv_key = vec![0u8; priv_key_size as usize];
        if unsafe {
            BCryptExportKey(
                ephemeral_key,
                BCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPRIVATE_BLOB,
                Some(&mut priv_key),
                &mut priv_key_size,
                0,
            )
        }
        .is_err()
        {
            unsafe {
                let _ = BCryptDestroyKey(ephemeral_key);
                let _ = BCryptDestroyKey(bcrypt_key);
            };
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        unsafe {
            let _ = BCryptDestroyKey(ephemeral_key);
            let _ = BCryptDestroyKey(bcrypt_key);
        }

        Ok((pub_key, priv_key))
    }
}

impl TpmProvider {
    fn get_key_length(&self, alg_handle: BCRYPT_ALG_HANDLE) -> Result<u32, SecurityModuleError> {
        let mut result: u32 = 0;

        // Buffer to receive the key length
        let mut key_length_buf: [u8; 4] = [0; 4];

        // Get the key length for the algorithm
        if unsafe {
            BCryptGetProperty(
                alg_handle,
                BCRYPT_KEY_LENGTH,
                Some(&mut key_length_buf),
                &mut result,
                0,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        let key_length = u32::from_le_bytes(key_length_buf);

        Ok(key_length)
    }
}

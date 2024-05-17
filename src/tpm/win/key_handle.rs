use super::TpmProvider;
use crate::{
    common::{error::SecurityModuleError, traits::key_handle::KeyHandle},
    tpm::core::error::TpmError,
};
use tracing::instrument;
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
        BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider, NCryptDecrypt,
        NCryptEncrypt, NCryptSignHash, NCryptVerifySignature, BCRYPT_ALG_HANDLE,
        BCRYPT_HASH_HANDLE, BCRYPT_HASH_LENGTH, BCRYPT_OBJECT_LENGTH,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, NCRYPT_FLAGS, NCRYPT_PAD_PKCS1_FLAG,
    },
};

/// Provides cryptographic operations for asymmetric keys on Windows,
/// such as signing, encryption, decryption, and signature verification.
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
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
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
        if unsafe {
            NCryptSignHash(
                self.key_handle.as_ref(),
                None,                  // No padding info
                &hash,                 // Hash as a slice
                None,                  // No signature buffer yet
                &mut signature_size,   // Pointer to receive the size of the signature
                NCRYPT_PAD_PKCS1_FLAG, // Padding flag
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Allocate a buffer for the signature
        let mut signature = Vec::with_capacity(signature_size as usize);

        // Sign the hash
        if unsafe {
            NCryptSignHash(
                self.key_handle.as_ref(),
                None,                  // No padding info
                &hash,                 // Hash as a slice
                Some(&mut signature),  // Signature buffer as a mutable slice
                &mut signature_size,   // Pointer to receive the actual size of the signature
                NCRYPT_PAD_PKCS1_FLAG, // Padding flag
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

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
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let mut decrypted_data_len: u32 = 0;

        // First, determine the size of the decrypted data without actually decrypting
        if unsafe {
            NCryptDecrypt(
                self.key_handle.as_ref(),
                Some(encrypted_data), // Pass encrypted data as an Option<&[u8]>
                None, // Padding information as Option<*const c_void>, adjust based on your encryption scheme
                None, // Initially, no output buffer to get the required size
                &mut decrypted_data_len, // Receives the required size of the output buffer
                NCRYPT_FLAGS(0), // Flags, adjust as necessary
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Allocate a buffer for the decrypted data
        let mut decrypted_data = vec![0u8; decrypted_data_len as usize];

        // Perform the actual decryption
        if unsafe {
            NCryptDecrypt(
                self.key_handle.as_ref(),
                Some(encrypted_data), // Again, pass encrypted data as an Option<&[u8]>
                None, // Padding information as Option<*const c_void>, adjust based on your encryption scheme
                Some(&mut decrypted_data), // Now provide the output buffer
                &mut decrypted_data_len, // Receives the size of the decrypted data
                NCRYPT_FLAGS(0), // Flags, adjust as necessary
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

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
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        // First call to determine the size of the encrypted data
        let mut encrypted_data_len: u32 = 0;
        if unsafe {
            NCryptEncrypt(
                self.key_handle.as_ref(),
                Some(data),              // Input data as a slice
                None, // Padding information, adjust based on your encryption scheme
                None, // Initially, no output buffer to get the required size
                &mut encrypted_data_len, // Receive the required size of the output buffer
                NCRYPT_FLAGS(0), // Flags, adjust as necessary
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Allocate a buffer for the encrypted data
        let mut encrypted_data = vec![0u8; encrypted_data_len as usize];

        // Actual call to encrypt the data
        if unsafe {
            NCryptEncrypt(
                self.key_handle.as_ref(),
                Some(data),                // Input data as a slice
                None, // Padding information, adjust based on your encryption scheme
                Some(&mut encrypted_data), // Provide the output buffer
                &mut encrypted_data_len, // Receives the size of the encrypted data
                NCRYPT_FLAGS(0), // Flags, adjust as necessary
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

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
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        // Open an algorithm provider for SHA-256, just like in sign_data
        let mut alg_handle = BCRYPT_ALG_HANDLE::default();
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
}

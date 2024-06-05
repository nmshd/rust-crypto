use crate::common::error::SecurityModuleError;
use std::fmt::Debug;
#[cfg(feature = "linux")]
use tss_esapi::handles::KeyHandle as TssKeyHandle;
#[cfg(feature = "win")]
use windows::Win32::Security::Cryptography::NCRYPT_KEY_HANDLE;

/// An enum representing a generic key handle that can be used on different platforms.
///
/// This enum provides a platform-agnostic way to handle cryptographic keys. It has two variants:
///
/// - `Linux`: Used on Linux platforms, wrapping the `TssKeyHandle` type from the `tss_esapi` crate.
/// - `Windows`: Used on Windows platforms, wrapping the `NCRYPT_KEY_HANDLE` type from the `windows` crate.
///
/// By using this enum, you can write code that works with cryptographic keys on both Linux and Windows platforms
/// without having to worry about the underlying platform-specific types.
#[repr(C)]
#[cfg(any(feature = "linux", feature = "win"))]
pub enum GenericKeyHandle {
    #[cfg(feature = "linux")]
    Linux(TssKeyHandle),
    #[cfg(feature = "win")]
    Windows(NCRYPT_KEY_HANDLE),
}

/// Defines a common interface for cryptographic key operations.
///
/// This trait specifies methods for key operations such as signing data, encrypting,
/// decrypting, and verifying signatures. It's designed to be implemented by security
/// modules that manage cryptographic keys, ensuring a consistent interface for key
/// operations across different types of security modules. Implementors of this trait
/// must ensure thread safety.
pub trait KeyHandle: Send + Sync + Debug {
    /// Signs the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be signed.
    ///
    /// # Returns
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[tracing::instrument]
    fn sign_data(&self, _data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::InitializationError(
            "Method not implemented".to_owned(),
        ))
    }
    /// Decrypts the given encrypted data using the cryptographic key.
    ///
    /// # Arguments
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[tracing::instrument]
    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::InitializationError(
            "Method not implemented".to_owned(),
        ))
    }
    /// Encrypts the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[tracing::instrument]
    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        Err(SecurityModuleError::InitializationError(
            "Method not implemented".to_owned(),
        ))
    }
    /// Verifies the signature of the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data whose signature is to be verified.
    /// * `signature` - A byte slice representing the signature to be verified against the data.
    ///
    /// # Returns
    /// A `Result` containing a boolean indicating whether the signature is valid (`true`) or not (`false`),
    /// or a `SecurityModuleError` on failure.
    #[tracing::instrument]
    fn verify_signature(
        &self,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        Err(SecurityModuleError::InitializationError(
            "Method not implemented".to_owned(),
        ))
    }
}

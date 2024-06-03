use tracing::instrument;

use crate::{
    common::{error::SecurityModuleError, traits::key_handle::KeyHandle},
    tpm::android::knox::interface::jni::RustDef
};

use super::KnoxProvider;

/// Implements the `Provider` trait, providing cryptographic operations
/// such as signing, encryption, decryption, and signature verification for the TPM Knox Vault.
///
/// This implementation is specific to Samsung Knox Vault and uses the Android Keystore API for all cryptographic operations
/// In theory, this should also work for other TPMs on Android phones, but it is only tested with Samsung Knox Vault
impl KeyHandle for KnoxProvider {
    /// Signs data using the previously loaded cryptographic key.
    ///
    /// This method hashes the input data using SHA-256 and then signs the hash.
    /// The algorithm used for signing is determined by the currently loaded key.
    /// If no key is loaded, an Error is returned.
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
        RustDef::sign_data(&self.get_env()?, data)
    }

    /// Decrypts the data with the currently loaded key.
    /// The algorithm used for decryption is determined by the currently loaded key.
    /// If no key is loaded, an Error is returned.
    /// # Arguments
    ///
    /// * `encrypted_data` - The data to be decrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        RustDef::decrypt_data(&self.get_env()?, encrypted_data)
    }

    /// Encrypts the data with the currently loaded key.
    /// The algorithm used for Encryption is determined by the currently loaded key.
    /// If no key is loaded, an Error is returned.
    /// # Arguments
    ///
    /// * `data` - The data to be encrypted.
    ///
    /// # Returns
    ///
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    #[instrument]
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        RustDef::encrypt_data(&self.get_env()?, data)
    }

    /// Verifies a signature against the provided data.
    ///
    /// This method hashes the input data using SHA-256 and then verifies the signature with the currently loaded key.
    /// The algorithm used for verification is determined by the currently loaded key.
    /// If no key is loaded, an Error is returned.
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
        RustDef::verify_signature(&self.get_env()?, data, signature)
    }
}

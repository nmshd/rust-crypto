use super::{KnoxProvider};
use crate::{
    common::{error::SecurityModuleError, traits::key_handle::KeyHandle},
    tpm::android::knox::interface::jni::RustDef
};
use tracing::instrument;

/// Provides cryptographic operations for asymmetric keys on Windows,
/// such as signing, encryption, decryption, and signature verification.
impl KeyHandle for KnoxProvider {
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
        RustDef::sign_data(&self.get_env()?, data)
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
        RustDef::decrypt_data(&self.get_env()?, encrypted_data)
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
        RustDef::encrypt_data(&self.get_env()?, data)
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
        RustDef::verify_signature(&self.get_env()?, data, signature)
    }
}

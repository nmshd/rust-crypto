#[cfg(feature = "android")]
use crate::tpm::android::key_handle::{AndroidKeyHandle, AndroidKeyPairHandle};
use crate::{
    common::{error::SecurityModuleError, DHExchange},
    stub::{StubKeyHandle, StubKeyPairHandle},
};
use enum_dispatch::enum_dispatch;

/// Defines a common interface for cryptographic key operations.
///
/// This trait specifies methods for key operations such as signing data, encrypting,
/// decrypting, and verifying signatures. It's designed to be implemented by security
/// modules that manage cryptographic keys, ensuring a consistent interface for key
/// operations across different types of security modules. Implementors of this trait
/// must ensure thread safety.
#[enum_dispatch(KeyHandleImplEnum)]
pub(crate) trait KeyHandleImpl: Send + Sync {
    /// Encrypts the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;

    /// Decrypts the given encrypted data using the cryptographic key.
    ///
    /// # Arguments
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;

    fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError>;

    /// Returns the id of the key, which can be used with `load_key`.
    fn id(&self) -> Result<String, SecurityModuleError>;
}

#[enum_dispatch]
pub(crate) enum KeyHandleImplEnum {
    StubKeyHandle,
    #[cfg(feature = "android")]
    AndroidKeyHandle,
}

#[enum_dispatch(KeyPairHandleImplEnum)]
pub(crate) trait KeyPairHandleImpl: Send + Sync {
    /// Signs the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be signed.
    ///
    /// # Returns
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;

    /// Verifies the signature of the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data whose signature is to be verified.
    /// * `signature` - A byte slice representing the signature to be verified against the data.
    ///
    /// # Returns
    /// A `Result` containing a boolean indicating whether the signature is valid (`true`) or not (`false`),
    /// or a `SecurityModuleError` on failure.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError>;

    /// Encrypts the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;

    /// Decrypts the given encrypted data using the cryptographic key.
    ///
    /// # Arguments
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `SecurityModuleError` on failure.
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;
    fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError>;
    fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError>;
    fn start_dh_exchange(&self) -> Result<DHExchange, SecurityModuleError>;

    /// Returns the id of the key pair, which can be used with `load_key_pair`.
    fn id(&self) -> Result<String, SecurityModuleError>;
}

#[enum_dispatch]
pub(crate) enum KeyPairHandleImplEnum {
    StubKeyPairHandle,
    #[cfg(feature = "android")]
    AndroidKeyPairHandle,
}

pub(crate) trait DHKeyExchangeImpl: Send + Sync {
    /// Get the public key of the internal key pair to use for the other party
    fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError>;

    /// add an external public point and compute the shared secret. The raw secret is returned to use in another round of the key exchange
    fn add_external(&mut self, external_key: &[u8]) -> Result<Vec<u8>, SecurityModuleError>;

    /// add the final external Keypair, derive a symmetric key from the shared secret and store the key
    fn add_external_final(
        self,
        external_key: &[u8],
    ) -> Result<KeyHandleImplEnum, SecurityModuleError>;
}

pub(crate) enum DHKeyExchangeImplEnum {
    #[cfg(feature = "android")]
    Android,
    Stub,
}

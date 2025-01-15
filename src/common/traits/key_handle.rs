#![allow(dead_code)]
#[cfg(feature = "software")]
use crate::software::{
    key_handle::{SoftwareKeyHandle, SoftwareKeyPairHandle},
    provider::SoftwareDHExchange,
};
#[cfg(feature = "android")]
use crate::tpm::android::key_handle::{AndroidKeyHandle, AndroidKeyPairHandle};
#[cfg(feature = "apple-secure-enclave")]
use crate::tpm::apple_secure_enclave::key_handle::AppleSecureEnclaveKeyPair;

use crate::{
    common::{
        config::{KeyPairSpec, KeySpec},
        error::CalError,
        DHExchange, KeyHandle,
    },
    stub::{StubDHKeyExchange, StubKeyHandle, StubKeyPairHandle},
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
    /// A `Result` containing the encrypted data and the used iv as a `Vec<u8>` on success,
    /// where the first value is the data and the second the iv,
    /// or a `CalError` on failure.
    fn encrypt_data(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError>;

    /// Decrypts the given encrypted data using the cryptographic key.
    ///
    /// # Arguments
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    /// * `iv` - A byte slice representing the initialization vector used for encryption.
    ///
    /// # Returns
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `CalError` on failure.
    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError>;

    fn hmac(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;

    fn verify_hmac(&self, data: &[u8], hmac: &[u8]) -> Result<bool, CalError>;

    fn extract_key(&self) -> Result<Vec<u8>, CalError>;

    /// Returns the id of the key, which can be used with `load_key`.
    fn id(&self) -> Result<String, CalError>;

    /// Delete this key.
    fn delete(self) -> Result<(), CalError>;

    /// Returns the [KeySpec] the key was generated with.
    fn spec(&self) -> KeySpec;
}

#[enum_dispatch]
#[derive(Debug, Clone)]
pub(crate) enum KeyHandleImplEnum {
    StubKeyHandle,
    #[cfg(feature = "android")]
    AndroidKeyHandle,
    #[cfg(feature = "software")]
    SoftwareKeyHandle,
}

#[enum_dispatch(KeyPairHandleImplEnum)]
pub(crate) trait KeyPairHandleImpl: Send + Sync {
    /// Signs the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be signed.
    ///
    /// # Returns
    /// A `Result` containing the signature as a `Vec<u8>` on success, or a `CalError` on failure.
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;

    /// Verifies the signature of the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data whose signature is to be verified.
    /// * `signature` - A byte slice representing the signature to be verified against the data.
    ///
    /// # Returns
    /// A `Result` containing a boolean indicating whether the signature is valid (`true`) or not (`false`),
    /// or a `CalError` on failure.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError>;

    /// Encrypts the given data using the cryptographic key.
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the data to be encrypted.
    ///
    /// # Returns
    /// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `CalError` on failure.
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError>;

    /// Decrypts the given encrypted data using the cryptographic key.
    ///
    /// # Arguments
    /// * `encrypted_data` - A byte slice representing the data to be decrypted.
    ///
    /// # Returns
    /// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `CalError` on failure.
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError>;
    fn get_public_key(&self) -> Result<Vec<u8>, CalError>;
    fn extract_key(&self) -> Result<Vec<u8>, CalError>;
    fn start_dh_exchange(&self) -> Result<DHExchange, CalError>;

    /// Returns the id of the key pair, which can be used with `load_key_pair`.
    fn id(&self) -> Result<String, CalError>;

    /// Delete this key pair.
    fn delete(self) -> Result<(), CalError>;

    /// Returns the [KeyPairSpec] the key was generated with.
    fn spec(&self) -> KeyPairSpec;
}

#[enum_dispatch]
#[derive(Debug, Clone)]
pub enum KeyPairHandleImplEnum {
    StubKeyPairHandle,
    #[cfg(feature = "android")]
    AndroidKeyPairHandle,
    #[cfg(feature = "apple-secure-enclave")]
    AppleSecureEnclaveKeyPair,
    #[cfg(feature = "software")]
    SoftwareKeyPairHandle,
}

#[enum_dispatch]
#[derive(Debug)]
pub(crate) enum DHKeyExchangeImplEnum {
    StubDHKeyExchange,
    #[cfg(feature = "software")]
    SoftwareDHExchange,
}

#[enum_dispatch(DHKeyExchangeImplEnum)]
pub(crate) trait DHKeyExchangeImpl: Send + Sync {
    /// Get the public key of the internal key pair to use for the other party
    fn get_public_key(&self) -> Result<Vec<u8>, CalError>;

    /// add an external public point and compute the shared secret. The raw secret is returned to use in another round of the key exchange
    fn add_external(&mut self, external_key: &[u8]) -> Result<Vec<u8>, CalError>;

    /// add the final external Keypair, derive a symmetric key from the shared secret and store the key
    fn add_external_final(&mut self, external_key: &[u8]) -> Result<KeyHandle, CalError>;
}

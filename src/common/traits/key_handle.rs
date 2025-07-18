#![allow(dead_code)]
#[cfg(feature = "android")]
use crate::provider::android::{
    dh_exchange::AndroidDHExchange,
    key_handle::{AndroidKeyHandle, AndroidKeyPairHandle},
};
#[cfg(feature = "apple-secure-enclave")]
use crate::provider::apple_secure_enclave::key_handle::AppleSecureEnclaveKeyPair;
#[cfg(feature = "software")]
use crate::provider::software::{
    key_handle::{SoftwareKeyHandle, SoftwareKeyPairHandle},
    provider::SoftwareDHExchange,
};

#[cfg(not(any(feature = "android", feature = "software")))]
compile_error!(
    "Due to the use of enum dispatch a provider that supports KeyHandle and DHExchange \
    needs to be chosen as well: 'software', 'android'."
);

use crate::common::{
    config::{KeyPairSpec, KeySpec},
    error::CalError,
    DHExchange, KeyHandle,
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
    ///
    /// If the iv argument is empty, a new iv is generated.
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError>;

    /// Encrypt data.
    ///
    /// The iv is randomly generated.
    ///
    /// The resulting output is a pair of cipher text and generated iv: `(cipher_text, iv)`
    fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        self.encrypt_data(data, &vec![])
    }

    /// Encrypt data with the given iv.
    ///
    /// Some providers panic, if the iv is not the correct length.
    fn encrypt_with_iv(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        let (cipher_text, _) = self.encrypt_data(data, iv)?;
        Ok(cipher_text)
    }

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

    /// Derives an ephemeral key from this key as base with the same spec as the base key.
    ///
    /// A derived key is exportable if the base key (self) is exportable.
    ///
    /// This operation is deterministic, meaning the same nonce and key are always going to result in the same [KeyHandle].
    fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError>;

    /// Returns the raw key as binary.
    ///
    /// Most hardware based providers will return [CalError]
    /// with [CalErrorKind::NotImplemented](super::CalErrorKind::NotImplemented).
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

    /// Returns the raw public key as binary.
    fn get_public_key(&self) -> Result<Vec<u8>, CalError>;

    /// Returns the raw private key as binary.
    ///
    /// Most hardware based providers will return [CalError]
    /// with [CalErrorKind::NotImplemented](super::CalErrorKind::NotImplemented).
    fn extract_key(&self) -> Result<Vec<u8>, CalError>;

    /// [DEPRECATED]: Starts a [DHExchange].
    ///
    /// Some Providers might return [CalError]
    /// with [CalErrorKind::NotImplemented](super::CalErrorKind::NotImplemented).
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
    #[cfg(feature = "software")]
    SoftwareDHExchange,
    #[cfg(feature = "android")]
    AndroidDHExchange,
}

#[enum_dispatch(DHKeyExchangeImplEnum)]
pub(crate) trait DHKeyExchangeImpl: Send + Sync {
    /// Returns the id of the key pair, which can be used with `load_key_pair`.
    fn id(&self) -> Result<String, CalError>;

    /// Get the public key of the internal key pair to use for the other party
    fn get_public_key(&self) -> Result<Vec<u8>, CalError>;

    /// Derive client session keys (rx, tx) - client is the templator in your code
    fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError>;

    /// Derive server session keys (rx, tx) - server is the requestor in your code
    fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError>;

    fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError>;

    fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError>;
}

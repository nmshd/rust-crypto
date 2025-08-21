use crate::common::traits::key_handle::DHKeyExchangeImpl;
use crate::prelude::{CryptoHash, KDF};
use config::{KeyPairSpec, KeySpec, ProviderConfig, Spec};
use error::CalError;
use traits::key_handle::DHKeyExchangeImplEnum;
use traits::key_handle::{
    KeyHandleImpl, KeyHandleImplEnum, KeyPairHandleImpl, KeyPairHandleImplEnum,
};
use traits::module_provider::{ProviderImpl, ProviderImplEnum};

/// Configuration for providers, key and key pairs.
pub mod config;
/// Cryptographic algorithms or standards.
pub mod crypto;
/// Error representations.
pub mod error;
/// Functions used for creating providers.
pub mod factory;
pub(crate) mod traits;

// Do not delete this struct, it is a workaround for a bug in the code generation
#[doc(hidden)]
pub struct T {}

/// Abstraction of cryptographic providers.
///
/// [Provider] abstracts hardware, software and network based keystores.
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct Provider {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: ProviderImplEnum,
}

impl Provider {
    /// Creates a new symmetric key.
    pub fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        self.implementation
            .create_key(spec)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to create key"))
    }

    /// Loads an existing symmetric key identified by `key_id`.
    pub fn load_key(&mut self, id: String) -> Result<KeyHandle, CalError> {
        self.implementation
            .load_key(id)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to load key"))
    }

    /// Imports a symmetric key from raw data.
    pub fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        self.implementation
            .import_key(spec, data)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to import key"))
    }

    /// Creates a new asymmetric key pair.
    pub fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        self.implementation
            .create_key_pair(spec)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to create key pair"))
    }

    /// Loads an existing asymmetric keypair identified by `key_id`.
    pub fn load_key_pair(&mut self, id: String) -> Result<KeyPairHandle, CalError> {
        self.implementation
            .load_key_pair(id)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to load key pair"))
    }

    /// Imports an asymmetric key pair from raw data.
    pub fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        self.implementation
            .import_key_pair(spec, public_key, private_key)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to import key pair"))
    }

    /// Imports a public key only.
    pub fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        self.implementation
            .import_public_key(spec, public_key)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to import public key"))
    }

    /// Generates a key pair suited for a Diffie-Hellman Key Exchange.
    pub fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<DHExchange, CalError> {
        self.implementation
            .start_ephemeral_dh_exchange(spec)
            .inspect_err(
                |error| tracing::error!(error = %error, "Failed to start ephemeral DH exchange"),
            )
    }

    #[deprecated(note = "Non ephemeral dh exchanges are possibly insecure.")]
    #[allow(dead_code)]
    pub fn dh_exchange_from_keys(
        &mut self,
        public_key: &[u8],
        private_key: &[u8],
        spec: KeyPairSpec,
    ) -> Result<DHExchange, CalError> {
        self.implementation
            .dh_exchange_from_keys(public_key, private_key, spec)
    }

    /// Returns all keys stored in this provider.
    pub fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        self.implementation
            .get_all_keys()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to get all keys"))
    }

    /// Returns the name of this provider.
    #[must_use]
    pub fn provider_name(&self) -> String {
        self.implementation.provider_name()
    }

    /// Returns the capabilities of this provider.
    #[must_use]
    pub fn get_capabilities(&self) -> Option<ProviderConfig> {
        self.implementation.get_capabilities()
    }

    /// Derives a high-entropy key from a low-entropy password and a unique salt.
    pub fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        algorithm: KeySpec,
        kdf: KDF,
    ) -> Result<KeyHandle, CalError> {
        self.implementation
            .derive_key_from_password(password, salt, algorithm, kdf)
            .inspect_err(
                |error| tracing::error!(error = %error, "Failed to derive key from password"),
            )
    }

    #[deprecated(
        note = "This function was deprecated in favor of the [KeyHandle::derive_key] method."
    )]
    pub fn derive_key_from_base(
        &self,
        base_key: &[u8],
        key_id: u64,
        context: &str,
        spec: KeySpec,
    ) -> Result<KeyHandle, CalError> {
        self.implementation
            .derive_key_from_base(base_key, key_id, context, spec)
    }

    /// Generates random bytes.
    #[must_use]
    pub fn get_random(&self, len: usize) -> Vec<u8> {
        self.implementation.get_random(len)
    }

    /// Hashes the input using the specified hash algorithm.
    pub fn hash(&self, input: &[u8], hash: CryptoHash) -> Result<Vec<u8>, CalError> {
        self.implementation
            .hash(input, hash)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to hash input"))
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeyPairHandle {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: KeyPairHandleImplEnum,
}

/// Abstraction of asymmetric key pair handles.
impl KeyPairHandle {
    /// Encrypts the given data using the cryptographic key.
    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.implementation.encrypt_data(data).inspect_err(
            |error| tracing::error!(error = %error, "Failed to encrypt data with key pair"),
        )
    }

    /// Decrypts the given encrypted data using the cryptographic key.
    pub fn decrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.implementation.decrypt_data(data).inspect_err(
            |error| tracing::error!(error = %error, "Failed to decrypt data with key pair"),
        )
    }

    /// Signs the given data using the cryptographic key.
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.implementation
            .sign_data(data)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to sign data"))
    }

    /// Verifies the signature of the given data using the cryptographic key.
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        self.implementation
            .verify_signature(data, signature)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to verify signature"))
    }

    /// Returns the raw public key as binary.
    pub fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        self.implementation
            .get_public_key()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to get public key"))
    }

    /// Returns the raw private key as binary.
    ///
    /// Most hardware based providers will return [CalError]
    /// with [CalErrorKind::NotImplemented](super::CalErrorKind::NotImplemented).
    pub fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        self.implementation
            .extract_key()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to extract private key"))
    }

    #[deprecated(note = "Non ephemeral dh exchanges are possibly insecure.")]
    #[allow(dead_code)]
    pub fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        self.implementation.start_dh_exchange()
    }

    /// Returns the id of the key pair, which can be used with `load_key_pair`.
    pub fn id(&self) -> Result<String, CalError> {
        self.implementation
            .id()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to get key pair ID"))
    }

    /// Delete this key pair.
    pub fn delete(self) -> Result<(), CalError> {
        self.implementation
            .delete()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to delete key pair"))
    }

    /// Returns the [KeyPairSpec] the key was generated with.
    #[must_use]
    pub fn spec(&self) -> KeyPairSpec {
        self.implementation.spec()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeyHandle {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: KeyHandleImplEnum,
}

impl KeyHandle {
    /// Returns the raw key as binary.
    ///
    /// Most hardware based providers will return [CalError]
    /// with [CalErrorKind::NotImplemented](super::CalErrorKind::NotImplemented).
    pub fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        self.implementation
            .extract_key()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to extract key"))
    }

    #[deprecated(
        note = "Deprecated in favor of the more specific `encrypt` and `encrypt_with_iv` methods."
    )]
    pub fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        self.implementation.encrypt_data(data, iv)
    }

    /// Encrypt data.
    ///
    /// The iv is randomly generated.
    ///
    /// The resulting output is a pair of cipher text and generated iv: `(cipher_text, iv)`
    pub fn encrypt(&self, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        self.implementation
            .encrypt(data)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to encrypt data"))
    }

    /// Encrypt data with the given iv.
    ///
    /// Some providers panic, if the iv is not the correct length.
    pub fn encrypt_with_iv(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        self.implementation
            .encrypt_with_iv(data, iv)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to encrypt data with IV"))
    }

    /// Decrypts the given encrypted data using the cryptographic key.
    pub fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        self.implementation
            .decrypt_data(encrypted_data, iv)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to decrypt data"))
    }

    /// Calculates HMAC of the given data.
    pub fn hmac(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.implementation
            .hmac(data)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to calculate HMAC"))
    }

    /// Verifies data with the given signature.
    pub fn verify_hmac(&self, data: &[u8], hmac: &[u8]) -> Result<bool, CalError> {
        self.implementation
            .verify_hmac(data, hmac)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to verify HMAC"))
    }

    /// Derives an ephemeral key from this key as base with the same spec as the base key.
    ///
    /// A derived key is exportable if the base key (self) is exportable.
    ///
    /// This operation is deterministic, meaning the same nonce and key are always going to result in the same [KeyHandle].
    pub fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError> {
        self.implementation
            .derive_key(nonce)
            .inspect_err(|error| tracing::error!(error = %error, "Failed to derive key"))
    }

    /// Returns the id of the key, which can be used with `load_key`.
    pub fn id(&self) -> Result<String, CalError> {
        self.implementation
            .id()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to get key ID"))
    }

    /// Delete this key.
    pub fn delete(self) -> Result<(), CalError> {
        self.implementation
            .delete()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to delete key"))
    }

    /// Returns the [KeySpec] the key was generated with.
    #[must_use]
    pub fn spec(&self) -> KeySpec {
        self.implementation.spec()
    }
}

#[allow(dead_code)]
#[derive(Debug)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct DHExchange {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: DHKeyExchangeImplEnum,
}

impl DHExchange {
    /// Returns the id of the key pair, which can be used with `load_key_pair`.
    pub fn id(&self) -> Result<String, CalError> {
        self.implementation
            .id()
            .inspect_err(|error| tracing::error!(error = %error, "Failed to get DH exchange ID"))
    }

    /// Get the public key of the internal key pair to use for the other party.
    pub fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        self.implementation.get_public_key().inspect_err(
            |error| tracing::error!(error = %error, "Failed to get DH exchange public key"),
        )
    }

    /// Derive client session keys (rx, tx) - client is the templator in your code.
    pub fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        self.implementation
            .derive_client_session_keys(server_pk)
            .inspect_err(
                |error| tracing::error!(error = %error, "Failed to derive client session keys"),
            )
    }

    /// Derive server session keys (rx, tx) - server is the requestor in your code.
    pub fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        self.implementation
            .derive_server_session_keys(client_pk)
            .inspect_err(
                |error| tracing::error!(error = %error, "Failed to derive server session keys"),
            )
    }

    /// Derives client session keys and returns them as key handles.
    pub fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        self.implementation
            .derive_client_key_handles(server_pk)
            .inspect_err(
                |error| tracing::error!(error = %error, "Failed to derive client key handles"),
            )
    }

    /// Derives server session keys and returns them as key handles.
    pub fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        self.implementation
            .derive_server_key_handles(client_pk)
            .inspect_err(
                |error| tracing::error!(error = %error, "Failed to derive server key handles"),
            )
    }
}

#[cfg(feature = "android")]
use crate::provider::android::wrapper::context;
#[cfg(feature = "android")]
use std::ffi::c_void;
#[cfg(feature = "android")]
pub unsafe fn initialize_android_context(java_vm: *mut c_void, context_jobject: *mut c_void) {
    context::initialize_android_context(java_vm, context_jobject);
}

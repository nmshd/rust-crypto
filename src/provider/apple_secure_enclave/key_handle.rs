use std::fmt;

use anyhow::anyhow;
use base64::prelude::*;
use security_framework::key::Algorithm;
use security_framework::key::SecKey;
use tracing::instrument;

use crate::common::config::KeyPairSpec;
use crate::common::error::ToCalError;
use crate::common::{
    crypto::algorithms::hashes::CryptoHash,
    error::{CalError, KeyType},
    traits::key_handle::KeyPairHandleImpl,
    DHExchange,
};
use crate::provider::apple_secure_enclave::CFErrorThreadSafe;
use crate::storage::StorageManager;

#[instrument(level = "trace")]
fn signature_algorithm_from_crypto_hash(hash: CryptoHash) -> Result<Algorithm, CalError> {
    match hash {
        CryptoHash::Sha2_224 => Ok(Algorithm::ECDSASignatureMessageX962SHA224),
        CryptoHash::Sha2_256 => Ok(Algorithm::ECDSASignatureMessageX962SHA256),
        CryptoHash::Sha2_384 => Ok(Algorithm::ECDSASignatureMessageX962SHA384),
        CryptoHash::Sha2_512 => Ok(Algorithm::ECDSASignatureMessageX962SHA512),
        _ => Err(CalError::bad_parameter(
            "Only Sha2 is supported.".to_owned(),
            true,
            None,
        )),
    }
}

fn encryption_algorithm_from_spec(spec: &KeyPairSpec) -> Result<Algorithm, CalError> {
    if let Some(cipher) = spec.cipher {
        if !matches!(
            cipher,
            crate::prelude::Cipher::AesGcm128 | crate::prelude::Cipher::AesGcm256
        ) {
            return Err(CalError::bad_parameter(
                format!(
                    "Apple secure enclave ECIES only supports AES GCM not '{:?}'.",
                    cipher
                ),
                true,
                None,
            ));
        }

        match spec.signing_hash {
            CryptoHash::Sha2_224 => {
                Ok(Algorithm::ECIESEncryptionStandardVariableIVX963SHA224AESGCM)
            }
            CryptoHash::Sha2_256 => {
                Ok(Algorithm::ECIESEncryptionStandardVariableIVX963SHA256AESGCM)
            }
            CryptoHash::Sha2_384 => {
                Ok(Algorithm::ECIESEncryptionStandardVariableIVX963SHA384AESGCM)
            }
            CryptoHash::Sha2_512 => {
                Ok(Algorithm::ECIESEncryptionStandardVariableIVX963SHA512AESGCM)
            }
            _ => Err(CalError::bad_parameter(
                format!(
                    "Apple secure enclave provider does not support the requested algorithm: '{:?}'.",
                    spec.signing_hash
                ),
                true,
                None,
            )),
        }
    } else {
        Err(CalError::bad_parameter(
            "Key was not initialized with a cipher.",
            true,
            None,
        ))
    }
}

#[derive(Clone)]
pub(crate) struct AppleSecureEnclaveKeyPair {
    pub(super) key_handle: SecKey,
    pub(super) spec: KeyPairSpec,
    pub(super) storage_manager: Option<StorageManager>,
}

impl KeyPairHandleImpl for AppleSecureEnclaveKeyPair {
    #[instrument(level = "trace", skip(data))]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        self.key_handle
            .create_signature(
                signature_algorithm_from_crypto_hash(self.spec.signing_hash)?,
                data,
            )
            .err_internal()
    }

    #[instrument(level = "trace", skip(data, signature))]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        let public_key: SecKey = self.key_handle.public_key().ok_or(CalError::missing_key(
            "SecKeyCopyPublicKey returned NULL".to_owned(),
            KeyType::Public,
        ))?;
        public_key
            .verify_signature(
                signature_algorithm_from_crypto_hash(self.spec.signing_hash)?,
                data,
                signature,
            )
            .err_internal()
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        let algorithm = encryption_algorithm_from_spec(&self.spec)?;
        self.key_handle
            .encrypt_data(algorithm, data)
            .map_err(|err| {
                CalError::failed_operation(
                    "Apple secure enclave failed encryption.",
                    false,
                    Some(anyhow!(CFErrorThreadSafe::from(err))),
                )
            })
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        let algorithm = encryption_algorithm_from_spec(&self.spec)?;
        self.key_handle
            .decrypt_data(algorithm, encrypted_data)
            .map_err(|err| {
                CalError::failed_operation(
                    "Apple secure enclave failed decryption.",
                    false,
                    Some(anyhow!(CFErrorThreadSafe::from(err))),
                )
            })
    }

    #[instrument(level = "trace", skip_all)]
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        let public_key: SecKey = self.key_handle.public_key().ok_or(CalError::missing_key(
            "SecKeyCopyPublicKey returned NULL".to_owned(),
            KeyType::Public,
        ))?;
        let external_representation =
            public_key
                .external_representation()
                .ok_or(CalError::missing_value(
                    "SecKeyCopyExternalRepresentation returned NULL".to_owned(),
                    false,
                    None,
                ))?;
        Ok(Vec::from(external_representation.bytes()))
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    #[instrument(level = "trace", skip_all)]
    fn id(&self) -> Result<String, CalError> {
        match self.key_handle.application_label() {
            None => Err(CalError::missing_value(
                "kSecAttrApplicationLabel missing for this key".to_owned(),
                false,
                None,
            )),
            Some(bytes) => Ok(BASE64_STANDARD.encode(bytes)),
        }
    }

    #[instrument]
    fn delete(self) -> Result<(), CalError> {
        if let Some(storage_manager) = &self.storage_manager {
            storage_manager.delete(self.id()?)?;
        }
        self.key_handle.delete().err_internal()
    }

    fn spec(&self) -> KeyPairSpec {
        self.spec
    }
}

impl fmt::Debug for AppleSecureEnclaveKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppleSecureEnclaveKeyPair")
            .field("key_handle", &self.key_handle)
            .field("metadata", &self.spec)
            .finish()
    }
}

impl Drop for AppleSecureEnclaveKeyPair {
    fn drop(&mut self) {
        if self.storage_manager.is_none() {
            if let Err(e) = self.key_handle.delete() {
                tracing::warn!("Failed to delete ephemeral key on device: {:?}", e);
            }
        }
    }
}

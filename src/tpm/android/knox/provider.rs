use super::TpmProvider;
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{AsymmetricEncryption, BlockCiphers, EccSchemeAlgorithm},
                hashes::Hash,
            },
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::module_provider::Provider,
    },
    tpm::core::error::TpmError,
};
use tracing::instrument;
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, BCRYPT_ECDH_ALGORITHM, BCRYPT_ECDSA_ALGORITHM, CERT_KEY_SPEC,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_ALLOW_SIGNING_FLAG,
        NCRYPT_CERTIFICATE_PROPERTY, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_OVERWRITE_KEY_FLAG,
        NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
    },
};
use std::error::Error;
use std::fmt;
use serde::de::Unexpected::Option;
use tss_esapi::constants::Tss2ResponseCodeKind::KeySize;
use tss_esapi::interface_types::algorithm::SymmetricAlgorithm;
use crate::common::crypto::algorithms::KeyBits;
use crate::tpm::linux::TpmProvider;


/// Implements the `Provider` trait, providing cryptographic operations utilizing a TPM.
///
/// This implementation is specific to the Windows platform and utilizes the Windows CNG API
/// to interact with the Trusted Platform Module (TPM) for key management and cryptographic
/// operations.
impl Provider for TpmProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method creates a persisted cryptographic key using the specified algorithm
    /// and identifier, making it retrievable for future operations. The key is created
    /// with the specified key usages and stored in the TPM.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm to be used with the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn create_key(&mut self, key_id: &str) -> Result<(), SecurityModuleError> {

        Ok(())
    }

    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method attempts to load a persisted cryptographic key by its identifier from the TPM.
    /// If successful, it sets the key usages and returns a handle to the key for further
    /// cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `key_algorithm` - The asymmetric encryption algorithm used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm used with the key.
    /// * `hash` - An optional hash algorithm used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    fn load_key(&mut self, key_id: &str) -> Result<(), SecurityModuleError> {

        Ok(())
    }

    /// Initializes the TPM module and returns a handle for cryptographic operations.
    ///
    /// This method opens a storage provider using the Windows CNG API and wraps it in a
    /// `WindowsProviderHandle`. This handle is used for subsequent cryptographic operations
    /// with the TPM.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.



    fn initialize_module(
        mut self,
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<(), SecurityModuleError> {

        let asymString;
        match key_algorithm {
            AsymmetricEncryption::Rsa(bitslength) => {
                match bitslength {
                    KeyBits::Bits128 => {asymString = String::from("RSA;128;HmacSHA1;PKCS1")}
                    KeyBits::Bits192 => {asymString = String::from("RSA;192;HmacSHA224;PKCS1")}
                    KeyBits::Bits256 => {asymString = String::from("RSA;256;HmacSHA384;PKCS1")}
                    KeyBits::Bits512 => {asymString = String::from("RSA;512;HmacSHA512;PKCS1")}
                    KeyBits::Bits1024 => {asymString = String::from("RSA;1024;HmacSHA512;PKCS1")}
                    KeyBits::Bits2048 => {asymString = String::from("RSA;2048;HmacSHA512;PKCS1")}
                    KeyBits::Bits3072 => {asymString = String::from("RSA;3072;HmacSHA512;PKCS1")}
                    KeyBits::Bits4096 => {asymString = String::from("RSA;4096;HmacSHA512;PKCS1")}
                    KeyBits::Bits8192 => {asymString = String::from("RSA;8192;HmacSHA512;PKCS1")}
                }
            }
            _ => {return Err(SecurityModuleError::UnsupportedAlgorithm(format!("Unsupported asymmetric encryption algorithm:")))}
        }

        let symString;
        match sym_algorithm {
            Option::Aes(bitslength) => {
                match bitslength {
                    KeyBits::Bits128 => {symString = String::from("AES;128;GCM;NoPadding")},
                    KeyBits::Bits128 => {symString = String::from("AES;128;ECB;PKCS7")},
                    KeyBits::Bits128 => {symString = String::from("AES;128;CBC;PKCS7")},
                    KeyBits::Bits128 => {symString = String::from("AES;128;CTR;PKCS7")},
                    KeyBits::Bits192 => {symString = String::from("AES;192;GCM;NoPadding")},
                    KeyBits::Bits192 => {symString = String::from("AES;192;ECB;PKCS7")},
                    KeyBits::Bits192 => {symString = String::from("AES;192;CBC;PKCS7")},
                    KeyBits::Bits192 => {symString = String::from("AES;192;CTR;PKCS7")},
                    KeyBits::Bits256 => {symString = String::from("AES;256;GCM;NoPadding")},
                    KeyBits::Bits256 => {symString = String::from("AES;256;ECB;PKCS7")},
                   KeyBits::Bits256 => {symString = String::from("AES;256;CBC;PKCS7")},
                    KeyBits::Bits256 => {symString = String::from("AES;256;CTR;PKCS7")},

                }
            },
            _ => {return Err(SecurityModuleError::UnsupportedAlgorithm(format!("Unsupported symmetric encryption algorithm:")))}
        }

        Ok(())
    }

}

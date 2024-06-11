use super::TpmProvider;
use crate::{
    common::{
        crypto::{
            algorithms::encryption::{AsymmetricEncryption, EccSchemeAlgorithm},
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::module_provider::Provider,
    },
    tpm::{core::error::TpmError, TpmConfig},
};
use std::any::Any;
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
    fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn Any>,
    ) -> Result<(), SecurityModuleError> {
        let config = config.downcast_ref::<TpmConfig>().unwrap();

        self.key_algo = Some(config.key_algorithm);
        self.sym_algo = Some(config.sym_algorithm);
        self.hash = Some(config.hash);
        self.key_usages = Some(config.key_usages.clone());

        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let alg_id: PCWSTR = match self.key_algo.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(key_bits) => {
                let key_bits_u32: u32 = (*key_bits).into();
                let rsa_alg_id: String = format!("RSA{}", key_bits_u32);
                PCWSTR(rsa_alg_id.as_ptr() as *const u16)
            }
            AsymmetricEncryption::Ecc(ecc_scheme) => match ecc_scheme {
                EccSchemeAlgorithm::EcDsa(_) => BCRYPT_ECDSA_ALGORITHM,
                EccSchemeAlgorithm::EcDh(_) => BCRYPT_ECDH_ALGORITHM,
                _ => unimplemented!(),
            },
        };

        let key_cu16 = PCWSTR(key_id.as_ptr() as *const u16);

        if unsafe {
            NCryptCreatePersistedKey(
                self.handle.as_ref(),
                &mut key_handle,
                alg_id,
                key_cu16,
                CERT_KEY_SPEC(0),
                NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG,
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        if let AsymmetricEncryption::Rsa(key_bits) = self.key_algo.as_ref().unwrap() {
            // Set the key length for RSA keys
            let key_length: u32 = (*key_bits).into();
            let key_length_bytes = key_length.to_le_bytes(); // Convert the key length to bytes
            if unsafe {
                NCryptSetProperty(
                    key_handle,             // Convert the handle into the expected parameter type
                    NCRYPT_LENGTH_PROPERTY, // Convert the property name into the expected parameter type
                    &key_length_bytes,      // Provide the property value as a byte slice
                    NCRYPT_SILENT_FLAG,     // Flags
                )
            }
            .is_err()
            {
                return Err(TpmError::Win(windows::core::Error::from_win32()).into());
            }
        }

        // Finalize the key creation
        if unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        for usage in self.key_usages.as_ref().unwrap() {
            match usage {
                KeyUsage::ClientAuth => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_KEY_USAGE_PROPERTY,
                            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
                KeyUsage::Decrypt => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_KEY_USAGE_PROPERTY,
                            &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
                KeyUsage::SignEncrypt => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_KEY_USAGE_PROPERTY,
                            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
                KeyUsage::CreateX509 => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_CERTIFICATE_PROPERTY,
                            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
            }
        }

        self.key_handle = Some(key_handle);
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
    fn load_key(&mut self, key_id: &str, config: Box<dyn Any>) -> Result<(), SecurityModuleError> {
        let config = config.downcast_ref::<TpmConfig>().unwrap();

        self.key_algo = Some(config.key_algorithm);
        self.sym_algo = Some(config.sym_algorithm);
        self.hash = Some(config.hash);
        self.key_usages = Some(config.key_usages.clone());

        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_cu16 = PCWSTR(key_id.as_ptr() as *const u16);

        if unsafe {
            NCryptOpenKey(
                *self.handle.as_ref().unwrap(),
                &mut key_handle,
                key_cu16,
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        }
        .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        // Set key usages
        for usage in self.key_usages.as_ref().unwrap() {
            match usage {
                KeyUsage::ClientAuth => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_KEY_USAGE_PROPERTY,
                            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
                KeyUsage::Decrypt => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_KEY_USAGE_PROPERTY,
                            &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
                KeyUsage::SignEncrypt => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_KEY_USAGE_PROPERTY,
                            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
                KeyUsage::CreateX509 => {
                    if unsafe {
                        NCryptSetProperty(
                            key_handle,
                            NCRYPT_CERTIFICATE_PROPERTY,
                            &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                            NCRYPT_SILENT_FLAG,
                        )
                    }
                    .is_err()
                    {
                        return Err(TpmError::Win(windows::core::Error::from_win32()).into());
                    }
                }
            }
        }

        self.key_handle = Some(key_handle);
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
    #[instrument]
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        let mut handle = NCRYPT_PROV_HANDLE::default();

        if unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
            .is_err()
        {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
        }

        Ok(())
    }
}

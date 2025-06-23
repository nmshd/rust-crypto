use super::TpmProvider;
use crate::{
    common::{
        crypto::{
            algorithms::encryption::{AsymmetricEncryption, EccSchemeAlgorithm},
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::{module_provider::Provider, module_provider_config::ProviderConfig},
    },
    tpm::{core::error::TpmError, win::execute_ncrypt_function, TpmConfig},
};
use async_trait::async_trait;
use tracing::instrument;
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptOpenKey, NCryptOpenStorageProvider,
        NCryptSetProperty, BCRYPT_ECDH_ALGORITHM, BCRYPT_ECDSA_ALGORITHM, CERT_KEY_SPEC,
        MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_ALLOW_SIGNING_FLAG,
        NCRYPT_CERTIFICATE_PROPERTY, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_KEY_USAGE_PROPERTY,
        NCRYPT_LENGTH_PROPERTY, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_PROV_HANDLE,
        NCRYPT_RSA_ALGORITHM, NCRYPT_SILENT_FLAG,
    },
};

/// Implements the `Provider` trait, providing cryptographic operations utilizing a TPM.
///
/// This implementation is specific to the Windows platform and utilizes the Windows CNG API
/// to interact with the Trusted Platform Module (TPM) for key management and cryptographic
/// operations.
#[async_trait]
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
    async fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        let config = config.as_any().await.downcast_ref::<TpmConfig>().unwrap();

        self.key_algo = config.key_algorithm;
        self.sym_algo = config.sym_algorithm;
        self.hash = config.hash;
        self.key_usages = config.key_usages.clone();

        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let alg_id: PCWSTR = match self.key_algo.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => NCRYPT_RSA_ALGORITHM,
            AsymmetricEncryption::Rsa(_) => NCRYPT_RSA_ALGORITHM,
            AsymmetricEncryption::Ecc(ecc_scheme) => match ecc_scheme {
                EccSchemeAlgorithm::EcDsa(_) => BCRYPT_ECDSA_ALGORITHM,
                EccSchemeAlgorithm::EcDh(_) => BCRYPT_ECDH_ALGORITHM,
                _ => unimplemented!(),
            },
        };

        let key_cu16 = PCWSTR(key_id.as_ptr() as *const u16);

        execute_ncrypt_function!(NCryptCreatePersistedKey(
            self.provider_handle.as_ref(),
            &mut key_handle,
            alg_id,
            key_cu16,
            CERT_KEY_SPEC(0),
            //NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG, // The program does not have the permissions.
            NCRYPT_OVERWRITE_KEY_FLAG,
        ));
        execute_ncrypt_function!(NCryptCreatePersistedKey(
            self.provider_handle.as_ref(),
            &mut key_handle,
            alg_id,
            key_cu16,
            CERT_KEY_SPEC(0),
            //NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG, // The program does not have the permissions.
            NCRYPT_OVERWRITE_KEY_FLAG,
        ));

        if let AsymmetricEncryption::Rsa(key_bits) = self.key_algo.as_ref().unwrap() {
            let key_length: u32 = (*key_bits).into();
            let key_length_bytes = key_length.to_le_bytes();

            //TODO Write code that tests that the RSA-Key is not too long for current TPM provider.

            execute_ncrypt_function!(NCryptSetProperty(
                key_handle,             // Convert the handle into the expected parameter type
                NCRYPT_LENGTH_PROPERTY, // Convert the property name into the expected parameter type
                &key_length_bytes,      // Provide the property value as a byte slice
                NCRYPT_SILENT_FLAG,     // Flags
            ));
            let key_length: u32 = (*key_bits).into();
            let key_length_bytes = key_length.to_le_bytes();

            //TODO Write code that tests that the RSA-Key is not too long for current TPM provider.

            execute_ncrypt_function!(NCryptSetProperty(
                key_handle,             // Convert the handle into the expected parameter type
                NCRYPT_LENGTH_PROPERTY, // Convert the property name into the expected parameter type
                &key_length_bytes,      // Provide the property value as a byte slice
                NCRYPT_SILENT_FLAG,     // Flags
            ));
        }

        //TODO Set EcDsa or EcDh Properties.

        for usage in self.key_usages.as_ref().unwrap() {
            match usage {
                KeyUsage::ClientAuth => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ));
                }
                KeyUsage::Decrypt => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ));
                }
                KeyUsage::SignEncrypt => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ));
                }
                KeyUsage::CreateX509 => {
                    //TODO NCRYPT_CERTIFICATE_PROPERTY sets a Blob with the x.509 certificate.
                    // See <https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers>;
                    /* execute_ncrypt_function!(dbg!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_CERTIFICATE_PROPERTY,
                        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ))); */
                }
            }
        }

        // Finalize the key creation
        if unsafe { NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) }.is_err() {
            return Err(TpmError::Win(windows::core::Error::from_win32()).into());
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
    async fn load_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        let config = config.as_any().await.downcast_ref::<TpmConfig>().unwrap();

        self.key_algo = config.key_algorithm;
        self.sym_algo = config.sym_algorithm;
        self.hash = config.hash;
        self.key_usages = config.key_usages.clone();

        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_cu16 = PCWSTR(key_id.as_ptr() as *const u16);

        execute_ncrypt_function!(NCryptOpenKey(
            *self.provider_handle.as_ref().unwrap(),
            &mut key_handle,
            key_cu16,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ));
        execute_ncrypt_function!(NCryptOpenKey(
            *self.provider_handle.as_ref().unwrap(),
            &mut key_handle,
            key_cu16,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ));

        // Set key usages
        for usage in self.key_usages.as_ref().unwrap() {
            match usage {
                KeyUsage::ClientAuth => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ))
                }
                KeyUsage::Decrypt => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &NCRYPT_ALLOW_DECRYPT_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ))
                }
                KeyUsage::SignEncrypt => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_KEY_USAGE_PROPERTY,
                        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ))
                }
                KeyUsage::CreateX509 => {
                    execute_ncrypt_function!(NCryptSetProperty(
                        key_handle,
                        NCRYPT_CERTIFICATE_PROPERTY,
                        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
                        NCRYPT_SILENT_FLAG,
                    ))
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
    async fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        let mut handle = NCRYPT_PROV_HANDLE::default();

        execute_ncrypt_function!(NCryptOpenStorageProvider(
            &mut handle,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0
        ));

        self.provider_handle = Some(handle);

        Ok(())
    }
}

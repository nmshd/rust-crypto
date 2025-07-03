use crate::{
    common::{
        config::{ProviderConfig, ProviderImplConfig, SecurityLevel},
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher},
            hashes::CryptoHash,
        },
        traits::module_provider::{ProviderFactory, ProviderImplEnum},
    },
    prelude::CalError,
    storage::StorageManager,
};

use anyhow::anyhow;
use std::collections::HashSet;
use tracing::debug;
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{
        // NCrypt handles and functions
        NCryptFreeObject,
        NCryptOpenStorageProvider,
        // NCrypt KSP name
        MS_PLATFORM_CRYPTO_PROVIDER,
        // NCrypt algorithm names
        NCRYPT_AES_ALGORITHM,
        NCRYPT_ECDSA_P256_ALGORITHM,
        NCRYPT_ECDSA_P384_ALGORITHM,
        NCRYPT_ECDSA_P521_ALGORITHM,
        NCRYPT_PROV_HANDLE,
        NCRYPT_RSA_ALGORITHM,
        NCRYPT_SHA256_ALGORITHM,
        NCRYPT_SHA384_ALGORITHM,
        NCRYPT_SHA512_ALGORITHM,
    },
};

// Module declarations for provider implementation and key handle implementation
pub(crate) mod key_handle;
pub(crate) mod provider;

#[derive(Default)]
pub(crate) struct WindowsProviderFactory {}

impl ProviderFactory for WindowsProviderFactory {
    fn get_name(&self) -> Option<String> {
        Some("WindowsTpmProvider".to_owned())
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        let mut supported_asym_specs = HashSet::new();
        supported_asym_specs.insert(AsymmetricKeySpec::RSA2048);
        supported_asym_specs.insert(AsymmetricKeySpec::RSA3072);
        supported_asym_specs.insert(AsymmetricKeySpec::RSA4096);
        supported_asym_specs.insert(AsymmetricKeySpec::P256);
        supported_asym_specs.insert(AsymmetricKeySpec::P384);
        supported_asym_specs.insert(AsymmetricKeySpec::P521);

        let mut cipher_set = HashSet::new();
        cipher_set.insert(Cipher::AesGcm128);
        cipher_set.insert(Cipher::AesGcm256);

        let mut supported_hashes = HashSet::new();
        supported_hashes.insert(CryptoHash::Sha2_256);
        supported_hashes.insert(CryptoHash::Sha2_384);
        supported_hashes.insert(CryptoHash::Sha2_512);

        Some(ProviderConfig {
            min_security_level: SecurityLevel::Hardware,
            max_security_level: SecurityLevel::Hardware,
            supported_asym_spec: supported_asym_specs,
            supported_ciphers: cipher_set,
            supported_hashes,
        })
    }

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        let mut h_prov = NCRYPT_PROV_HANDLE::default();

        execute_ncrypt_function!(@result NCryptOpenStorageProvider(
            &mut h_prov,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0
        ))?;

        let provider_handle = NcryptProvHandleWrapper(h_prov);

        let storage_manager =
            StorageManager::new(self.get_name().unwrap(), &impl_config.additional_config)?;

        Ok(Into::into(WindowsProvider {
            impl_config,
            storage_manager,
            provider_handle,
        }))
    }
}

/// Wrapper for NCRYPT_PROV_HANDLE to ensure NCryptFreeObject is called on drop.
#[derive(Debug)]
pub(super) struct NcryptProvHandleWrapper(pub NCRYPT_PROV_HANDLE);

impl Drop for NcryptProvHandleWrapper {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // NCryptFreeObject returns a SECURITY_STATUS, but we can't easily propagate
            // errors from drop. We'll log it if it fails.
            // NCRYPT_OBJECT_HANDLE is a type alias for NCRYPT_HANDLE which is usize.
            // NCRYPT_PROV_HANDLE is also NCRYPT_HANDLE.
            let result = unsafe { NCryptFreeObject(self.0.into()) };
            if result.is_err() {
                debug!(
                    "Failed to free NCRYPT_PROV_HANDLE {:?}: {:?}",
                    self.0, result
                );
            }
        }
    }
}

// Ensure the wrapper can be sent across threads if the underlying handle can.
// NCRYPT_PROV_HANDLE is essentially a pointer/usize, so it's Send + Sync.
unsafe impl Send for NcryptProvHandleWrapper {}
unsafe impl Sync for NcryptProvHandleWrapper {}

pub(crate) struct WindowsProvider {
    impl_config: ProviderImplConfig,
    storage_manager: Option<StorageManager>,
    pub(super) provider_handle: NcryptProvHandleWrapper,
}

/// Macro to execute NCrypt/BCrypt functions and convert errors.
macro_rules! execute_ncrypt_function {
    // Arm 1: For functions that already return Result<T, windows::core::Error>
    // Example: NCryptOpenStorageProvider returns Result<(), windows::core::Error>
    // Usage: execute_ncrypt_function!(@result NCryptOpenStorageProvider(...))
    (@result $func_returning_result:expr) => {
        match unsafe { $func_returning_result } { // $func_returning_result is already a Result<T, Error>
            Ok(val) => Ok(val), // val is T (can be () or an actual value)
            Err(e) => Err(CalError::failed_operation(
                format!("Windows API call (Result) failed: {}", e), // Clarified message
                true,
                Some(anyhow!(e)),
            )),
        }
    };

    // Arm 2: For functions that return a status code (e.g., NTSTATUS, HRESULT directly)
    // which has a .ok() method converting it to Result<(), windows::core::Error>.
    // Example: BCryptGenRandom returns NTSTATUS. BCryptGetProperty returns NTSTATUS.
    // Usage: execute_ncrypt_function!(BCryptGenRandom(...))
    ($func_returning_status_code:expr) => {
        // unsafe { $func_returning_status_code } evaluates to the status code (e.g., NTSTATUS)
        // .ok() is then called on this status code, converting it to Result<(), windows::core::Error>
        match unsafe { $func_returning_status_code }.ok() {
            Ok(()) => Ok(()), // This now correctly matches on Result<(), windows::core::Error>
            Err(win_error) => Err(CalError::failed_operation(
                format!("Windows API call (Status Code) failed: {}", win_error), // Clarified message
                true,
                Some(anyhow!(win_error)),
            )),
        }
    };
}
pub(super) use execute_ncrypt_function;

pub(super) fn cipher_to_pcwstr(cipher: Cipher) -> Result<PCWSTR, CalError> {
    match cipher {
        Cipher::AesGcm128 | Cipher::AesGcm256 => Ok(NCRYPT_AES_ALGORITHM),
        _ => Err(CalError::unsupported_algorithm(format!(
            "Cipher {cipher:?} is not supported by WindowsTpmProvider"
        ))),
    }
}

pub(super) fn crypto_hash_to_pcwstr(hash: CryptoHash) -> Result<PCWSTR, CalError> {
    match hash {
        CryptoHash::Sha2_256 => Ok(NCRYPT_SHA256_ALGORITHM),
        CryptoHash::Sha2_384 => Ok(NCRYPT_SHA384_ALGORITHM),
        CryptoHash::Sha2_512 => Ok(NCRYPT_SHA512_ALGORITHM),
        _ => Err(CalError::unsupported_algorithm(format!(
            "CryptoHash {hash:?} is not supported by WindowsTpmProvider"
        ))),
    }
}

// Helper to get key length in bytes for symmetric keys
pub(super) fn get_symmetric_key_length_bytes(cipher: Cipher) -> Result<usize, CalError> {
    match cipher {
        Cipher::AesGcm128 => Ok(128 / 8),
        Cipher::AesGcm256 => Ok(256 / 8),
        _ => Err(CalError::unsupported_algorithm(format!(
            "Cannot determine key length for Cipher {cipher:?}"
        ))),
    }
}

// Helper to get key length in bits for asymmetric keys
pub(super) fn get_asymmetric_key_length_bits(spec: AsymmetricKeySpec) -> Result<u32, CalError> {
    match spec {
        AsymmetricKeySpec::RSA1024 => Ok(1024),
        AsymmetricKeySpec::RSA2048 => Ok(2048),
        AsymmetricKeySpec::RSA3072 => Ok(3072),
        AsymmetricKeySpec::RSA4096 => Ok(4096),
        AsymmetricKeySpec::RSA8192 => Ok(8192),
        AsymmetricKeySpec::P256 => Ok(256),
        AsymmetricKeySpec::P384 => Ok(384),
        AsymmetricKeySpec::P521 => Ok(521),
        _ => Err(CalError::unsupported_algorithm(format!(
            "Cannot determine key length for AsymmetricKeySpec {spec:?}"
        ))),
    }
}

pub(super) fn asymmetric_spec_to_pcwstr(spec: AsymmetricKeySpec) -> Result<PCWSTR, CalError> {
    match spec {
        AsymmetricKeySpec::RSA1024
        | AsymmetricKeySpec::RSA2048
        | AsymmetricKeySpec::RSA3072
        | AsymmetricKeySpec::RSA4096
        | AsymmetricKeySpec::RSA8192 => Ok(NCRYPT_RSA_ALGORITHM),
        AsymmetricKeySpec::P256 => Ok(NCRYPT_ECDSA_P256_ALGORITHM),
        AsymmetricKeySpec::P384 => Ok(NCRYPT_ECDSA_P384_ALGORITHM),
        AsymmetricKeySpec::P521 => Ok(NCRYPT_ECDSA_P521_ALGORITHM),
        _ => Err(CalError::unsupported_algorithm(format!(
            "AsymmetricKeySpec {spec:?} is not supported by WindowsTpmProvider"
        ))),
    }
}

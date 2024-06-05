use crate::{common::traits::module_provider::Provider, tpm::macos::SecureEnclaveProvider};
#[cfg(feature = "linux")]
use crate::tpm::linux::TpmProvider;
#[cfg(feature = "win")]
use crate::tpm::win::TpmProvider as WinTpmProvider;
use std::sync::{Arc, Mutex};

/// Represents the different environments where a Trusted Platform Module (TPM) can operate.
///
/// This enum is designed to distinguish between various operating system environments,
/// including Windows, macOS, Linux, and Android-specific TPM types. It provides a unified
/// way to handle TPM operations across different platforms.
#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug)]
pub enum TpmType {
    /// Represents the TPM environment on Windows platforms.
    #[cfg(feature = "win")]
    Windows,
    /// Represents the TPM environment on macOS platforms.
    #[cfg(feature = "macos")]
    MacOs,
    /// Represents the TPM environment on Linux platforms.
    #[cfg(feature = "linux")]
    Linux,
    /// Represents the TPM environment on Android platforms, with a specific `AndroidTpmType`.
    #[cfg(feature = "android")]
    Android(AndroidTpmType),
    /// Represents an unsupported or unknown TPM environment.
    None,
}

/// Enumerates the types of TPM available on Android platforms.
///
/// Currently, this enum includes a single variant, `Knox`, which represents
/// Samsung's Knox security platform that incorporates TPM functionalities.
#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug)]
#[cfg(feature = "android")]
pub enum AndroidTpmType {
    /// Represents the Samsung Knox security platform with TPM functionalities.
    Knox,
}

/// Provides a default `TpmType` based on the compile-time target operating system.
///
/// This implementation enables automatic selection of the TPM type most appropriate
/// for the current target OS, facilitating platform-agnostic TPM handling.
impl Default for TpmType {
    #[allow(unreachable_code)]
    fn default() -> Self {
        #[cfg(feature = "win")]
        return TpmType::Windows;

        #[cfg(feature = "macos")]
        return TpmType::MacOs;

        #[cfg(feature = "linux")]
        return TpmType::Linux;

        #[cfg(feature = "android")]
        return TpmType::Android(AndroidTpmType::Knox);

        TpmType::None
    }
}

/// Enables conversion from a string slice to a `TpmType`.
///
/// This implementation allows for dynamic TPM type determination based on string values,
/// useful for configuration or runtime environment specification.
impl From<&str> for TpmType {
    fn from(s: &str) -> Self {
        match s {
            #[cfg(feature = "win")]
            "Windows" => TpmType::Windows,
            #[cfg(feature = "macos")]
            "MacOs" => TpmType::MacOs,
            #[cfg(feature = "linux")]
            "Linux" => TpmType::Linux,
            #[cfg(feature = "android")]
            "Android" => TpmType::Android(AndroidTpmType::Knox),
            _ => panic!("Unsupported TpmType"),
        }
    }
}

/// Manages instances of TPM providers based on the specified `TpmType`.
///
/// This structure is responsible for creating and encapsulating a TPM provider instance,
/// allowing for TPM operations such as key management and cryptographic functions
/// to be performed in a platform-specific manner.
#[repr(C)]
pub struct TpmInstance {
    name: String,
    instance: Box<dyn Provider>,
}

/// Facilitates the creation and management of TPM provider instances.
impl TpmInstance {
    /// Creates a new TPM provider instance based on the specified `TpmType`.
    ///
    /// This method abstracts over the differences between TPM implementations across
    /// various platforms, providing a unified interface for TPM operations.
    ///
    /// # Arguments
    /// * `key_id` - A unique identifier for the TPM key.
    /// * `tpm_type` - A reference to the `TpmType` indicating the environment of the TPM.
    ///
    /// # Returns
    /// An `Arc<dyn Provider>` encapsulating the created TPM provider instance.
    pub fn create_instance(key_id: String, tpm_type: &TpmType) -> Arc<Mutex<dyn Provider>> {
        match tpm_type {
            #[cfg(feature = "win")]
            TpmType::Windows => {
                let instance = WinTpmProvider::new(key_id);
                Arc::new(Mutex::new(instance))
            }
            #[cfg(feature = "macos")]
            TpmType::MacOs => {
                let instance = SecureEnclaveProvider::new(key_id);
                Arc::new(Mutex::new(instance))
            },
            #[cfg(feature = "linux")]
            TpmType::Linux => {
                let instance = TpmProvider::new(key_id);
                Arc::new(Mutex::new(instance))
            }
            #[cfg(feature = "android")]
            TpmType::Android(_tpm_type) => todo!(),
            TpmType::None => todo!(),
        }
    }
}

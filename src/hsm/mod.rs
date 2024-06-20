/// # High-Level Overview
///
/// This module provides configuration structures for hardware security module (HSM) providers.
/// It includes the `HsmProviderConfig` structure, which encapsulates information about the
/// cryptographic algorithms and key usages supported by the HSM provider.
///
/// ## Module Structure
///
/// The module consists of the following components:
///
/// - `core`: Contains core functionality for HSM providers.
/// - `nitrokey`: Provides support for Nitrokey HSM devices.
/// - `yubikey`: Offers support for YubiKey HSM devices (conditionally compiled with the `yubi` feature).
///
/// ## `HsmProviderConfig` Structure
///
/// The `HsmProviderConfig` struct defines the configuration parameters for an HSM provider. It contains:
///
/// - `key_algorithm`: Specifies the asymmetric encryption algorithm supported by the HSM.
/// - `key_usage`: Specifies the key usages supported by the HSM.
///
/// ## Usage
///
/// To use this module, follow these steps:
///
/// 1. Import the required modules: `crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage}`.
/// 2. Define a new configuration using `HsmProviderConfig::new`.
/// 3. Pass the configuration to the HSM provider for initialization.
///
/// ## Example
///
/// ```rust
/// use crate::common::crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage};
/// use crate::common::traits::module_provider_config::ProviderConfig;
///
/// // Import the HSM provider configuration module
/// use crate::hsm::HsmProviderConfig;
///
/// // Define the HSM configuration with RSA encryption and key usage for signing and encryption
/// let config = HsmProviderConfig::new(
///     AsymmetricEncryption::Rsa(KeyBits::Bits2048),
///     vec![KeyUsage::SignEncrypt],
/// );
///
/// // Pass the configuration to the HSM provider for initialization
/// let provider = initialize_hsm_provider(config);
/// ```
use crate::common::crypto::algorithms::encryption::AsymmetricEncryption;
use crate::common::traits::module_provider_config::ProviderConfig;

/// The core functionality for hardware security module (HSM) providers.
pub mod core;

/// Provides support for Nitrokey HSM devices.
pub mod nitrokey;

use std::any::Any;

/// Provides support for YubiKey HSM devices (conditionally compiled with the `yubi` feature).
#[cfg(feature = "yubi")]
pub mod yubikey;

/// Configuration parameters for an HSM provider.
#[derive(Debug)]
pub struct HsmProviderConfig {
    /// The asymmetric encryption algorithm supported by the HSM.
    pub(super) key_algorithm: AsymmetricEncryption,
}

impl ProviderConfig for HsmProviderConfig {
    /// Returns a reference to the dynamic `Any` trait object.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl HsmProviderConfig {
    /// Creates a new instance of `HsmProviderConfig`.
    ///
    /// # Arguments
    ///
    /// - `key_algorithm`: The asymmetric encryption algorithm supported by the HSM.
    /// - `key_usage`: The key usages supported by the HSM.
    ///
    /// # Returns
    ///
    /// A boxed trait object representing the HSM provider configuration.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(key_algorithm: AsymmetricEncryption) -> Box<dyn Any> {
        Box::new(Self { key_algorithm })
    }
}

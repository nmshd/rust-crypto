use super::key_handle::KeyHandle;
use crate::common::error::SecurityModuleError;
use std::{any::Any, fmt::Debug};

/// Defines the interface for a security module provider.
///
/// This trait encapsulates operations related to cryptographic processing, such as
/// data encryption/decryption and signing/verification, as well as key management through
/// a `ProviderHandle`. It ensures a unified approach to interacting with different types
/// of security modules.
///
/// Implementors of this trait must also implement the `KeyHandle` trait to provide
/// cryptographic key operations.
pub trait Provider: Send + Sync + KeyHandle + Debug {
    /// Creates a new cryptographic key identified by `key_id`.
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
    fn create_key(&mut self, key_id: &str, config: Box<dyn Any>)
        -> Result<(), SecurityModuleError>;

    /// Loads an existing cryptographic key identified by `key_id`.
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
    fn load_key(&mut self, key_id: &str, config: Box<dyn Any>) -> Result<(), SecurityModuleError>;

    /// Initializes the security module and returns a handle for further operations.
    ///
    /// This method should be called before performing any other operations with the security module.
    /// It initializes the module and prepares it for use.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError>;
}

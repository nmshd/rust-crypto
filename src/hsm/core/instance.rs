use crate::common::traits::module_provider::Provider;
use std::sync::{Arc, Mutex};

/// Represents the types of HSMs supported by the HSM system.
///
/// This enumeration lists all the HSM types that can be used with the HSM system. Currently,
/// it supports YubiKey and NitroKey HSMs. This enum can be easily extended to support additional
/// HSM types in the future.
///
/// # Variants
///
/// - `YubiKey`: Represents a YubiKey HSM.
/// - `NitroKey`: Represents a NitroKey HSM.
///
/// # Examples
///
/// Converting from a string to a `HsmType`:
///
/// ```
/// let HSM_type: HsmType = "YubiKey".into();
/// assert_eq!(HSM_type, HsmType::YubiKey);
/// ```
#[repr(C)]
#[derive(Eq, Hash, PartialEq, Default, Clone, Debug)]
pub enum HsmType {
    #[default]
    NitroKey,
    YubiKey,
}

// Implement From<&str> for HsmType to convert string arguments into enum variants.
impl From<&str> for HsmType {
    /// Converts a string slice into a `HsmType` enum variant.
    ///
    /// This implementation allows for creating `HsmType` variants from string literals,
    /// facilitating easier parsing and handling of HSM types from text sources.
    ///
    /// # Panics
    ///
    /// Panics if the string does not match any of the supported HSM types.
    ///
    /// # Parameters
    ///
    /// - `s`: A string slice representing the HSM type.
    ///
    /// # Returns
    ///
    /// A `HsmType` variant corresponding to the input string.
    fn from(s: &str) -> Self {
        match s {
            "YubiKey" => HsmType::YubiKey,
            "NitroKey" => HsmType::NitroKey,
            _ => panic!("Unsupported HsmType"),
        }
    }
}

/// A representation of an HSM instance.
///
/// This struct encapsulates the information and functionality related to an instance of a
/// hardware security module (HSM). It holds the name of the HSM and an instance of a provider
/// that implements the `Provider` trait, facilitating interactions with the HSM.
///
/// # Fields
///
/// - `name`: A `String` holding the name of the HSM instance.
/// - `instance`: A boxed trait object that implements the `Provider` trait, representing the
/// provider for this HSM instance.
///
/// # Methods
///
/// - `create_instance`: A method to create a new HSM instance based on the HSM type.
#[repr(C)]
pub struct HsmInstance {
    name: String,
    instance: Box<dyn Provider>,
}

impl HsmInstance {
    /// Creates a new instance of a provider based on the specified HSM type.
    ///
    /// This method initializes an HSM instance according to the HSM type provided.
    /// It is currently stubbed with `todo!()`, indicating that the implementation is incomplete
    /// and needs to be provided.
    ///
    /// # Parameters
    ///
    /// - `_key_id`: A `String` specifying the key identifier for the HSM instance.
    /// - `hpm_type`: A reference to a `HsmType` specifying the type of HSM for the HSM instance.
    ///
    /// # Returns
    ///
    /// An `Arc<Mutex<dyn Provider>>`, wrapping the provider for the HSM instance in a thread-safe
    /// reference-counting pointer.
    pub fn create_instance(_key_id: String, hpm_type: &HsmType) -> Arc<Mutex<dyn Provider>> {
        match hpm_type {
            HsmType::YubiKey => todo!(),
            HsmType::NitroKey => todo!(),
        }
    }
}

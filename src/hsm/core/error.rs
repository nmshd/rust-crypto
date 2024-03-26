use std::fmt;

/// Represents errors that can occur within a Hardware Security Module (HSM).
///
/// This enum classifies errors into four categories: communication issues with the HSM,
/// authentication failures, device-specific errors, and attempts to use unsupported features.
/// It includes implementations for `fmt::Display` to allow these errors to be formatted as
/// human-readable strings, and `std::error::Error` to integrate with Rust's error handling mechanisms.
///
/// # Variants
///
/// - `Communication(std::io::Error)`: Wraps `std::io::Error` indicating problems with I/O operations.
/// - `Authentication(String)`: Represents errors related to authentication failures, with a message describing the issue.
/// - `DeviceSpecific(String)`: Encapsulates device-specific errors, with details provided in the message.
/// - `UnsupportedFeature(String)`: Indicates attempts to use a feature not supported by the HSM, with a message explaining which feature.
#[derive(Debug)]
#[repr(C)]
pub enum HsmError {
    Communication(std::io::Error),
    Authentication(String),
    DeviceSpecific(String),
    UnsupportedFeature(String),
}

impl fmt::Display for HsmError {
    /// Formats the `HsmError` variants into human-readable messages.
    ///
    /// This function matches each error variant and formats it with a descriptive message,
    /// facilitating easier debugging and logging.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HsmError::Communication(ref err) => write!(f, "Communication error: {}", err),
            HsmError::Authentication(ref msg) => write!(f, "Authentication error: {}", msg),
            HsmError::DeviceSpecific(ref msg) => write!(f, "Device-specific error: {}", msg),
            HsmError::UnsupportedFeature(ref msg) => write!(f, "Unsupported feature: {}", msg),
        }
    }
}

impl std::error::Error for HsmError {
    /// Provides context for the error, primarily for `Communication` errors,
    /// by returning the underlying `std::io::Error` as a source.
    ///
    /// For other error types, it returns `None`, as they do not wrap other errors.
    #[tracing::instrument]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            HsmError::Communication(ref err) => Some(err),
            _ => None,
        }
    }
}

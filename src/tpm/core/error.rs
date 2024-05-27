use std::fmt;

/// Represents errors that can occur when interacting with a Trusted Platform Module (TPM).
///
/// This enum encapsulates different types of errors that may arise during TPM operations,
/// including I/O errors, Windows API errors, initialization errors, and unsupported operations.
/// It is designed to provide a clear and descriptive representation of the error, facilitating
/// error handling and logging.
#[derive(Debug)]
#[repr(C)]
pub enum TpmError {
    /// Error related to I/O operations, wrapping a `std::io::Error`.
    Io(std::io::Error),
    /// Error originating from Windows API calls, wrapping a `windows::core::Error`.
    /// This variant is only available on Windows platforms.
    #[cfg(feature = "win")]
    Win(windows::core::Error),
    /// Error occurring during TPM initialization, containing an error message.
    InitializationError(String),
    /// Error indicating that an attempted operation is unsupported, containing a description.
    UnsupportedOperation(String),
    /// Error indicating that an internal error occured, possibly caused by ffi bindings
    InternalError(Box<dyn std::error::Error>),
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl TpmError {
    /// Provides a human-readable description of the TPM error.
    ///
    /// This implementation ensures that errors can be easily logged or displayed to the user,
    /// with a clear indication of the error's nature and origin.
    pub fn description(&self) -> String {
        match self {
            TpmError::Io(err) => format!("IO error: {}", err),
            #[cfg(feature = "win")]
            TpmError::Win(err) => format!("Windows error: {}", err),
            TpmError::InitializationError(msg) => format!("Initialization error: {}", msg),
            TpmError::UnsupportedOperation(msg) => format!("Unsupported operation: {}", msg),
            TpmError::InternalError(e) => format!("Internal error: {}", e),
        }
    }
}

/// A trait to allow ergonomic conversions to TpmError
pub trait ToTpmError<T> {
    /// Wrap any error in TpmError::InternalError
    /// the wrapped error can be accessed througth the error trait
    fn err_internal(self) -> Result<T, TpmError>;
}

/// Enables `TpmError` to be treated as a trait object for any error (`dyn std::error::Error`).
///
/// This implementation allows for compatibility with Rust's standard error handling mechanisms,
/// facilitating the propagation and inspection of errors through the `source` method.
impl std::error::Error for TpmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TpmError::Io(ref err) => Some(err),
            #[cfg(feature = "win")]
            TpmError::Win(ref err) => Some(err),
            // `InitializationError` and `UnsupportedOperation` do not wrap another error,
            // so they return `None` for their source.
            _ => None,
        }
    }
}

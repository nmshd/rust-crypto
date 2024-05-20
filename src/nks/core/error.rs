use std::fmt;
use std::fmt::{Display, Formatter};

/// Represents errors that can occur when interacting with a Network Key Storage (nks).
///
/// This enum encapsulates different types of errors that may arise during nks operations,
/// including I/O errors, HashiCorp Vault API errors, initialization errors, and unsupported operations.
/// It is designed to provide a clear and descriptive representation of the error, facilitating
/// error handling and logging.
#[derive(Debug)]
#[repr(C)]
pub enum NksError {
    /// Error related to I/O operations, wrapping a `std::io::Error`.
    Io(std::io::Error),
    //TODO implement hcvault errors
    /*
    /// Error originating from HashiCorp Vault API calls, wrapping a `hcvault::core::Error`.
    /// This variant is only available with HaschiCorp Vault nks.
    #[cfg(feature = "hcvault")]
    Hcv(hcvault::core::Error),
     */
    /// Error occurring during nks initialization, containing an error message.
    InitializationError(String),
    /// Error indicating that an attempted operation is unsupported, containing a description.
    UnsupportedOperation(String),
}

//TODO implement fmt::Display for NksError
/*
impl fmt::Display for NksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

 */

impl NksError {
    /// Provides a human-readable description of the nks error.
    ///
    /// This implementation ensures that errors can be easily logged or displayed to the user,
    /// with a clear indication of the error's nature and origin.
    pub fn description(&self) -> &str {
        match self {
            NksError::ApiError(api_err) => api_err.description(),
            NksError::IoError(io_err) => io_err.description(),
            NksError::ParseError(parse_err) => parse_err.description(),
            // Add more error variants as needed
        }
    }
}

impl Display for NksError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

/// Enables `NksError` to be treated as a trait object for any error (`dyn std::error::Error`).
///
/// This implementation allows for compatibility with Rust's standard error handling mechanisms,
/// facilitating the propagation and inspection of errors through the `source` method.
impl std::error::Error for NksError {}
/*
/// Enables `NksError` to be treated as a trait object for any error (`dyn std::error::Error`).
///
/// This implementation allows for compatibility with Rust's standard error handling mechanisms,
/// facilitating the propagation and inspection of errors through the `source` method.

//TODO implement std::error::Error for NksError

impl std::error::Error for NksError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NksError::Io(ref err) => Some(err),
            #[cfg(feature = "win")]
            NksError::Win(ref err) => Some(err),
            // `InitializationError` and `UnsupportedOperation` do not wrap another error,
            // so they return `None` for their source.
            _ => None,
        }
    }
}

 */

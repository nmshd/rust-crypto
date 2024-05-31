#[cfg(feature = "tpm")]
use crate::tpm::core::error::TpmError;

#[cfg(feature = "hsm")]
use crate::hsm::core::error::HsmError;
use std::fmt;

/// Represents errors that can occur within a security module.
///
/// This enum encapsulates various types of errors, including those originating
/// from a Hardware Security Module (HSM), a Trusted Platform Module (TPM), or during
/// the initialization process. It also includes errors related to cryptographic operations
/// such as signing, decryption, encryption, and signature verification.
#[derive(Debug)]
#[repr(C)]
pub enum SecurityModuleError {
    #[cfg(feature = "hsm")]
    /// Error originating from a Hardware Security Module (HSM).
    Hsm(HsmError),
    #[cfg(feature = "tpm")]
    /// Error originating from a Trusted Platform Module (TPM).
    Tpm(TpmError),
    /// Error that occurred during the signing operation.
    ///
    /// This variant contains a descriptive error message.
    SigningError(String),
    /// Error that occurred during the decryption operation.
    ///
    /// This variant contains a descriptive error message.
    DecryptionError(String),
    /// Error that occurred during the encryption operation.
    ///
    /// This variant contains a descriptive error message.
    EncryptionError(String),
    /// Error that occurred during the signature verification operation.
    ///
    /// This variant contains a descriptive error message.
    SignatureVerificationError(String),
    /// Error that occurs during the initialization process.
    ///
    /// This variant contains a descriptive error message.
    InitializationError(String),
    /// Error that occurs during the create Key process.
    ///
    /// This variant contains a descriptive error message.
    CreateKeyError(String),
    /// Error that occurs during the load Key process.
    ///
    /// This variant contains a descriptive error message.
    LoadKeyError(String),
}

impl fmt::Display for SecurityModuleError {
    /// Provides a human-readable description of the security module error.
    ///
    /// Formats the error message based on the error type, ensuring that it is
    /// descriptive and easy to understand.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "hsm")]
            SecurityModuleError::Hsm(ref err) => {
                write!(f, "HSM error: {}", err)
            }
            #[cfg(feature = "tpm")]
            SecurityModuleError::Tpm(ref err) => {
                write!(f, "TPM error: {}", err)
            }
            SecurityModuleError::SigningError(ref error_msg) => {
                write!(f, "Signing error: {}", error_msg)
            }
            SecurityModuleError::DecryptionError(ref error_msg) => {
                write!(f, "Decryption error: {}", error_msg)
            }
            SecurityModuleError::EncryptionError(ref error_msg) => {
                write!(f, "Encryption error: {}", error_msg)
            }
            SecurityModuleError::SignatureVerificationError(ref error_msg) => {
                write!(f, "Signature verification error: {}", error_msg)
            }
            SecurityModuleError::InitializationError(ref error_msg) => {
                write!(f, "Initialization error: {}", error_msg)
            }
            SecurityModuleError::CreateKeyError(ref error_msg) => {
                write!(f, "Create Key error: {}", error_msg)
            }
            SecurityModuleError::LoadKeyError(ref error_msg) => {
                write!(f, "Load Key error: {}", error_msg)
            }
        }
    }
}

impl std::error::Error for SecurityModuleError {
    /// Provides the source of the security module error, if available.
    ///
    /// This method helps in understanding and diagnosing the underlying cause of the error,
    /// particularly useful when debugging or logging error information.
    ///
    /// For errors originating from an HSM or TPM, the source error is returned.
    /// For other error variants, `None` is returned, as they do not have an underlying source error.
    #[tracing::instrument]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            #[cfg(feature = "hsm")]
            SecurityModuleError::Hsm(ref err) => Some(err),
            #[cfg(feature = "tpm")]
            SecurityModuleError::Tpm(ref err) => Some(err),
            SecurityModuleError::SigningError(_) => None,
            SecurityModuleError::DecryptionError(_) => None,
            SecurityModuleError::EncryptionError(_) => None,
            SecurityModuleError::SignatureVerificationError(_) => None,
            SecurityModuleError::InitializationError(_) => None,
            SecurityModuleError::CreateKeyError(_) => None,
            SecurityModuleError::LoadKeyError(_) => None,
        }
    }
}

#[cfg(feature = "hsm")]
impl From<HsmError> for SecurityModuleError {
    /// Converts an `HsmError` into a `SecurityModuleError`.
    ///
    /// This conversion simplifies error handling by allowing direct use of `HsmError`
    /// values in contexts where `SecurityModuleError` is expected.
    #[tracing::instrument]
    fn from(err: HsmError) -> SecurityModuleError {
        SecurityModuleError::Hsm(err)
    }
}

#[cfg(feature = "tpm")]
impl From<TpmError> for SecurityModuleError {
    /// Converts a `TpmError` into a `SecurityModuleError`.
    ///
    /// Similar to the conversion from `HsmError`, this allows for streamlined error
    /// handling and propagation of `TpmError` values as `SecurityModuleError`.
    #[tracing::instrument]
    fn from(err: TpmError) -> SecurityModuleError {
        SecurityModuleError::Tpm(err)
    }
}

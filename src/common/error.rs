use std::convert::From;
use std::fmt;

use anyhow::anyhow;
use thiserror;

use crate::storage::{StorageManagerError, StorageManagerInitializationError};

// Feel free to add more items to error.

/// Error wrapping native errors.
///
/// The native libraries used large lists of errors that might occur.
/// This struct exists to dumb down said errors.
/// The provider implementation should map errors from native libraries to this enum.
/// Most if not all errors should have a source for backtraces.
/// If other fields are useful for understanding the error, they should also exist.
#[derive(thiserror::Error, Debug)]
#[error("{error_kind}: {source}")]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
#[repr(C)]
pub struct CalError {
    error_kind: CalErrorKind,

    #[cfg_attr(feature = "ts-interface", ts(skip))]
    source: anyhow::Error,
}

/// Enumeration differentiating between the causes and the severity of the error.
/// flutter_rust_bridge:non_opaque
#[derive(thiserror::Error, Debug, Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
#[repr(C)]
pub enum CalErrorKind {
    /// This error is returned on calling functions that are not implemented.
    #[error("The function called is not implemented.")]
    NotImplemented,

    /// One or more of the parameters supplied are invalid for said function.
    #[error("Bad Parameter Error: {description}")]
    BadParameter {
        description: String,
        /// `true` if caused within this library. `false` if caused by another library.
        internal: bool,
    },

    #[error("Missing Key Error: {key_type} key with id {key_id}")]
    MissingKey { key_id: String, key_type: KeyType },

    /// The value requested could not be found.
    #[error("Missing Value Error: {description}")]
    MissingValue {
        description: String,
        /// `true` if caused within this library. `false` if caused by another library.
        internal: bool,
    },

    /// A cryptographic operation failed.
    #[error("Failed Operation: {description}")]
    FailedOperation {
        description: String,
        /// `true` if caused within this library. `false` if caused by another library.
        internal: bool,
    },

    /// Failed to initialize a provider.
    #[error("Failed Initializing Provider: {description}")]
    InitializationError {
        description: String,
        /// `true` if caused within this library. `false` if caused by another library.
        internal: bool,
    },

    #[error("Key or key pair is non exportable.")]
    NonExportable,

    /// Algorithm requested is not supported by the provider.
    #[error("Unsupported Algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Tried to create a non-ephemeral key with an ephemeral provider.
    #[error("Ephemeral Key Error")]
    EphemeralKeyError,

    /// Errors that do not fall into the above classes.
    #[error("Other Error")]
    Other,
}

#[allow(dead_code)]
impl CalError {
    pub(crate) fn other(source: anyhow::Error) -> Self {
        Self {
            error_kind: CalErrorKind::Other,
            source,
        }
    }

    pub(crate) fn bad_parameter(
        description: impl Into<String>,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_kind: CalErrorKind::BadParameter {
                description: description.into(),
                internal,
            },
            source: source.unwrap_or_else(|| anyhow!("Bad Parameter Error")),
        }
    }

    pub(crate) fn not_implemented() -> Self {
        Self {
            error_kind: CalErrorKind::NotImplemented,
            source: anyhow!("Not Implemented Error"),
        }
    }

    pub(crate) fn missing_key(key_id: impl Into<String>, key_type: KeyType) -> Self {
        Self {
            error_kind: CalErrorKind::MissingKey {
                key_id: key_id.into(),
                key_type,
            },
            source: anyhow!("Missing Key Error"),
        }
    }

    pub(crate) fn missing_value(
        description: impl Into<String>,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_kind: CalErrorKind::MissingValue {
                description: description.into(),
                internal,
            },
            source: source.unwrap_or_else(|| anyhow!("Missing Value Error")),
        }
    }

    pub(crate) fn failed_operation(
        description: impl Into<String>,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_kind: CalErrorKind::FailedOperation {
                description: description.into(),
                internal,
            },
            source: source.unwrap_or_else(|| anyhow!("Failed Operation")),
        }
    }

    pub(crate) fn failed_init(
        description: impl Into<String>,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        CalError {
            error_kind: CalErrorKind::InitializationError {
                description: description.into(),
                internal,
            },
            source: source.unwrap_or_else(|| anyhow!("Initialization Error")),
        }
    }

    pub(crate) fn unsupported_algorithm(algorithm: impl Into<String>) -> Self {
        Self {
            error_kind: CalErrorKind::UnsupportedAlgorithm(algorithm.into()),
            source: anyhow!("Unsupported Algorithm Error"),
        }
    }

    pub(crate) fn initialization_error(description: impl Into<String>) -> Self {
        Self {
            error_kind: CalErrorKind::InitializationError {
                description: description.into(),
                internal: true,
            },
            source: anyhow!("Initialization Error"),
        }
    }

    pub(crate) fn non_exportable() -> Self {
        Self {
            error_kind: CalErrorKind::NonExportable,
            source: anyhow!("NonExportable Error"),
        }
    }

    pub(crate) fn ephemeral_key_required() -> Self {
        Self {
            error_kind: CalErrorKind::EphemeralKeyError,
            source: anyhow!("Ephemeral Key Error"),
        }
    }

    pub fn error_kind(&self) -> CalErrorKind {
        self.error_kind.clone()
    }

    pub fn backtrace(&self) -> String {
        self.source.backtrace().to_string()
    }
}

/// Key type for error pertaining to said key.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum KeyType {
    Public,
    Private,
    PublicAndPrivate,
    Symmetric,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private => write!(f, "private"),
            Self::Public => write!(f, "public"),
            Self::PublicAndPrivate => write!(f, "public and private"),
            Self::Symmetric => write!(f, "symmetric"),
        }
    }
}

#[allow(dead_code)]
pub(crate) trait ToCalError<T> {
    fn err_internal(self) -> Result<T, CalError>;
}

impl From<anyhow::Error> for CalError {
    fn from(value: anyhow::Error) -> Self {
        CalError::other(value)
    }
}

impl From<StorageManagerError> for CalError {
    fn from(value: StorageManagerError) -> Self {
        CalError::from(anyhow!(value))
    }
}

impl From<StorageManagerInitializationError> for CalError {
    fn from(value: StorageManagerInitializationError) -> Self {
        CalError::from(anyhow!(value))
    }
}

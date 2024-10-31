use std::fmt;

use anyhow::anyhow;
use thiserror;

// Feel free to add more items to error.

/// Error wrapping native errors.
///
/// The native libraries used large lists of errors that might occur.
/// This struct exists to dumm down said errors.
/// The provider implementation should map errors from native libraries to this enum.
/// Most if not all errors should have a source for backtraces.
/// If other fields are usefull for understanding the error, they should also exist.
///

#[derive(thiserror::Error, Debug)]
#[error("{error_kind}: {source}")]
#[repr(C)]
pub struct CalError {
    error_kind: CalErrorKind,
    source: anyhow::Error,
}

/// flutter_rust_bridge:non_opaque
#[derive(thiserror::Error, Debug, Clone)]
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

    #[error("Unsupported Algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Errors that do not fall into the above classes.
    #[error("Other Error")]
    Other,
}

#[allow(dead_code)]
impl CalError {
    pub(crate) fn other(source: anyhow::Error) -> Self {
        Self {
            error_kind: CalErrorKind::Other,
            source: source,
        }
    }

    pub(crate) fn bad_parameter(
        description: String,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_kind: CalErrorKind::BadParameter {
                description,
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

    pub(crate) fn missing_key(key_id: String, key_type: KeyType) -> Self {
        Self {
            error_kind: CalErrorKind::MissingKey { key_id, key_type },
            source: anyhow!("Missing Key Error"),
        }
    }

    pub(crate) fn missing_value(
        description: String,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_kind: CalErrorKind::MissingValue {
                description: description,
                internal,
            },
            source: source.unwrap_or_else(|| anyhow!("Missing Value Error")),
        }
    }

    pub(crate) fn failed_operation(
        description: String,
        internal: bool,
        source: Option<anyhow::Error>,
    ) -> Self {
        Self {
            error_kind: CalErrorKind::FailedOperation {
                description,
                internal,
            },
            source: source.unwrap_or_else(|| anyhow!("Failed Operation")),
        }
    }

    pub(crate) fn unsupported_algorithm(algorithm: String) -> Self {
        Self {
            error_kind: CalErrorKind::UnsupportedAlgorithm(algorithm),
            source: anyhow!("Unsupported Algorithm Error"),
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
pub enum KeyType {
    Public,
    Private,
    PublicAndPrivate,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Private => write!(f, "private"),
            Self::Public => write!(f, "public"),
            Self::PublicAndPrivate => write!(f, "public and private"),
        }
    }
}

pub(crate) trait ToCalError<T> {
    fn err_internal(self) -> Result<T, CalError>;
}

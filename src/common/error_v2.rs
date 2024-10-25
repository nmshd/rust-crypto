use core::error;
use std::fmt;

use anyhow;
use thiserror;

// Feel free to add more items to error.

/// Error enum wrapping native errors.
///
/// The native libraries used large lists of errors that might occur.
/// This enum exists to dumm down said errors.
/// The provider implementation should map errors from native libraries to this enum.
/// Most if not all errors should have a source for backtraces.
/// If other fields are usefull for understanding the error, they should also exist.
#[derive(thiserror::Error, Debug)]
#[repr(C)]
pub enum Error {
    /// This error is returned on calling functions that are not implemented.
    #[error("The function called is not implemented.")]
    NotImplemented,

    /// One or more of the parameters supplied are invalid for said function.
    #[error("Bad Parameter Error: {description}")]
    BadParameter {
        description: String,
        /// `true` if caused within this library. `false` if caused by another library.
        internal: bool,
        source: anyhow::Error,
    },

    #[error("Missing Key Error: {key_type} key with id {key_id}")]
    MissingKey {
        key_id: String,
        key_type: KeyType,
        source: anyhow::Error,
    },

    /// Errors that do not fall into the above classes.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Key type for error pertaining to said key.
#[derive(Debug)]
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

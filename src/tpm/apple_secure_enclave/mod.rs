pub mod key_handle;
pub mod provider;

use std::convert::From;

use anyhow::anyhow;
use core_foundation::error::CFError;
use security_framework::base;
use thiserror;

use crate::common::error::CalError;

/// CFError is not thread safe. This struct wraps CFError's output.
#[derive(thiserror::Error, Debug)]
#[error("{description}")]
struct CFErrorThreadSafe {
    domain: String,
    code: isize,
    description: String,
}

impl From<CFError> for CFErrorThreadSafe {
    fn from(value: CFError) -> Self {
        Self {
            domain: format!("{}", value.domain()),
            code: value.code(),
            description: format!("{}", value.description()),
        }
    }
}

impl From<CFError> for CalError {
    fn from(value: CFError) -> Self {
        match value.code() {
            _ => CalError::other(anyhow!(CFErrorThreadSafe::from(value))),
        }
    }
}

impl From<base::Error> for CalError {
    fn from(value: base::Error) -> Self {
        match value.code() {
            _ => CalError::other(anyhow!(value)),
        }
    }
}

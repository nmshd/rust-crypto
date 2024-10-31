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
#[error("{code} -- {description}")]
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

impl CalError {
    fn from_cferr(error: CFError, context: String) -> Self {
        let code = error.code();
        let wrapped_error = anyhow!(CFErrorThreadSafe::from(error));
        match code {
            0xFFFFFFCE
            | 0xFFFFFC73
            | 0xFFFFD99A
            | 0xFFFEF746
            | 0xFFFEF745
            | 0xFFFEFA48
            | 0xFFFF9D21
            | 0xFFFEF7FA
            | 0xFFFEF7F8
            | 0xFFFEF7F7
            | 0xFFFEF7F1
            | 0xFFFEF7EF
            | 0xFFFEF7EA
            | 0xFFFEF7E9
            | 0xFFFEF7E8
            | 0xFFFEF7E7
            | 0xFFFEF7D6
            | 0xFFFEF7D3
            | 0xFFFEF780
            | 0xFFFEF77F
            | 0xFFFEF76D
            | 0xFFFEF76C
            | 0xFFFEF76B
            | 0xFFFEF76A
            | 0xFFFEF769
            | 0xFFFEF768
            | 0xFFFEF767
            | 0xFFFEF766
            | 0xFFFEF765
            | 0xFFFEF764
            | 0xFFFEF763
            | 0xFFFEF762
            | 0xFFFEF75C
            | 0xFFFEF75B
            | 0xFFFEF74E
            | 0xFFFEF74D
            | 0xFFFEF742
            | 0xFFFEF741
            | 0xFFFEF723..=0xFFFEF72A
            | 0xFFFEF71D
            | 0xFFFEF6D7
            | 0xFFFEF723..=0xFFFEF75C => {
                CalError::bad_parameter(context, false, Some(wrapped_error))
            }
            0xFFFEFA4C | 0xFFFEFA44 | 0xFFFEFA24 | 0xFFFEFA1B | 0xFFFEFA0B | 0xFFFEF7F9
            | 0xFFFEF798 | 0xFFFEF6CA | 0xFFFFD9AB | 0xFFFEF79A | 0xFFFEF720 | 0xFFFEF71C
            | 0xFFFEF70F | 0xFFFFD9AF | 0xFFFFD9A3 | 0xFFFFD98B | 0xFFFFD986 | 0xFFFF9D56
            | 0xFFFF9D55 | 0xFFFF9D34 => {
                CalError::failed_operation(context, false, Some(wrapped_error))
            }
            0xFFFFFFFC | 0xFFFEFA00 => CalError::not_implemented(),
            0xFFFF9D32 | 0xFFFF9D35 | 0xFFFF9D31 | 0xFFFF9D28 | 0xFFFEF6E1 | 0xFFFEF6D8 => {
                CalError::missing_value(context, false, Some(wrapped_error))
            }
            _ => CalError::other(wrapped_error),
        }
    }
}

impl From<CFError> for CalError {
    fn from(value: CFError) -> Self {
        let description = format!("{}", value.description());
        Self::from_cferr(value, description)
    }
}

impl From<base::Error> for CalError {
    fn from(value: base::Error) -> Self {
        match value.code() {
            _ => CalError::other(anyhow!(value)),
        }
    }
}

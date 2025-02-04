use thiserror;
use tracing::error;

#[derive(thiserror::Error, Debug)]
pub(crate) enum ConversionError {
    #[error("The string given does not convert to the enum requested.")]
    EnumVariantNotFound,
    #[error("One or more of the given parameters are incorrect.")]
    BadParameter,
    #[error("Unexpected error while executing js component.")]
    JsError,
    #[error("RwLock is poisoned.")]
    RwLockPoisoned,
}

/// Used for errors which stem from internal logic (casting up and down).
pub fn js_result<R, E: std::fmt::Display>(res: Result<R, E>) -> Result<R, ConversionError> {
    match res {
        Ok(r) => Ok(r),
        Err(e) => {
            error!(error = %e, "{}", ConversionError::JsError);
            Err(ConversionError::JsError)
        }
    }
}

/// Used for errors which should not happen if the user used typescript to check his inputs.
pub fn bad_parameter<R, E: std::fmt::Display>(res: Result<R, E>) -> Result<R, ConversionError> {
    match res {
        Ok(r) => Ok(r),
        Err(e) => {
            error!(error = %e, "{}", ConversionError::BadParameter);
            Err(ConversionError::BadParameter)
        }
    }
}

/// Used for [std::sync::LockResult].
pub fn rw_lock_poisoned<R, E: std::fmt::Display>(res: Result<R, E>) -> Result<R, ConversionError> {
    match res {
        Ok(r) => Ok(r),
        Err(e) => {
            error!(error = %e, "{}", ConversionError::RwLockPoisoned);
            Err(ConversionError::RwLockPoisoned)
        }
    }
}

macro_rules! unwrap_or_throw {
    ($cx:ident, $e:expr) => {
        match $e {
            Ok(res) => res,
            Err(err) => {
                let msg = format!("{}", err);
                return $cx.throw_error(msg);
            }
        }
    };
}

pub(crate) use unwrap_or_throw;

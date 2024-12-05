use std::convert::From;

use neon::prelude::*;
use thiserror;

#[derive(thiserror::Error, Debug)]
pub(crate) enum ConversionError {
    #[error("The string given does not convert to the enum requested.")]
    EnumVariantNotFound,
    #[error(
        "One or more values are missing from the object to create the desired struct or enum."
    )]
    MissingEnumValues,
    #[error("One or more of the given parameters are incorrect.")]
    BadParameter,
    #[error("Unexpected error while executing js component.")]
    JsError,
}

impl ConversionError {
    pub fn to_js_error<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsError> {
        cx.error(format!("{}", self))
    }

    pub fn js_throw<T>(&self, cx: &mut FunctionContext) -> NeonResult<T> {
        let err = self.to_js_error(cx)?;
        cx.throw(err)
    }
}

pub fn match_variant_result<R, E>(res: Result<R, E>) -> Result<R, ConversionError> {
    match res {
        Ok(r) => Ok(r),
        Err(_) => Err(ConversionError::EnumVariantNotFound),
    }
}

pub fn js_result<R, E>(res: Result<R, E>) -> Result<R, ConversionError> {
    match res {
        Ok(r) => Ok(r),
        Err(_) => Err(ConversionError::JsError),
    }
}

pub fn missing_enum_values<R, E>(res: Result<R, E>) -> Result<R, ConversionError> {
    match res {
        Ok(r) => Ok(r),
        Err(_) => Err(ConversionError::MissingEnumValues),
    }
}

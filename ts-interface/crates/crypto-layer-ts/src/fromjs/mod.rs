pub(crate) mod config;
pub(crate) mod encryption;
pub(crate) mod hashes;
pub(crate) mod error;


use std::str::FromStr;

use neon::prelude::*;
use crypto_layer::prelude::*;

use error::{ConversionError, match_variant_result, js_result};

pub(crate) fn from_wrapped_string_vec<'a>(cx: &mut impl Context<'a>, wrapped_string_vec: Handle<'a, JsArray>) -> Result<Vec<String>, ConversionError> {
    let arr = js_result(wrapped_string_vec.to_vec(cx))?;
    let mut res = vec![];

    for elem in arr {
        if let Ok(s) = elem.downcast::<JsString, _>(cx) {
            res.push(s.value(cx));
        }
    }

    Ok(res)
}

pub(crate) fn from_wrapped_enum<'a, T: FromStr>(cx: &mut impl Context<'a>, wrapped_enum: Handle<JsValue>) -> Result<T, ConversionError> {
    if let Ok(s) = wrapped_enum.downcast::<JsString, _>(cx) {
        let value = s.value(cx);
        match_variant_result(T::from_str(&value))
    } else if let Ok(o)  = wrapped_enum.downcast::<JsObject, _>(cx) {
        let keys = js_result(o.get_own_property_names(cx))?;
        let unwrapped_keys = from_wrapped_string_vec(cx, keys)?;
        for key in unwrapped_keys {
            if let Ok(res) = T::from_str(&key) {
                return Ok(res);
            }
        }
        Err(ConversionError::EnumVariantNotFound)
    } else {
        Err(ConversionError::BadParameter)
    }
}
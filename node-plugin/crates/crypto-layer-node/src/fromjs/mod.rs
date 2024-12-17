pub(crate) mod config;
pub(crate) mod error;

use std::cmp::Eq;
use std::collections::HashSet;
use std::hash::Hash;
use std::str::FromStr;

use neon::prelude::*;

use error::{js_result, match_variant_result, ConversionError};

pub(crate) fn from_wrapped_string_vec<'a>(
    cx: &mut impl Context<'a>,
    wrapped_string_vec: Handle<'a, JsArray>,
) -> Result<Vec<String>, ConversionError> {
    let arr = js_result(wrapped_string_vec.to_vec(cx))?;
    let mut res = vec![];

    for elem in arr {
        if let Ok(s) = elem.downcast::<JsString, _>(cx) {
            res.push(s.value(cx));
        }
    }

    Ok(res)
}

pub(crate) fn object_keys<'a>(
    cx: &mut impl Context<'a>,
    obj: Handle<JsObject>,
) -> Result<Vec<String>, ConversionError> {
    let keys = js_result(obj.get_own_property_names(cx))?;
    let unwrapped_keys = from_wrapped_string_vec(cx, keys)?;
    Ok(unwrapped_keys)
}

pub(crate) fn from_wrapped_simple_enum<T: FromStr>(
    cx: &mut FunctionContext,
    wrapped_enum: Handle<JsValue>,
) -> Result<T, ConversionError> {
    let wrapped_as_str = js_result(wrapped_enum.downcast::<JsString, _>(cx))?;
    let enum_str = wrapped_as_str.value(cx);
    Ok(match_variant_result(T::from_str(&enum_str))?)
}

pub(crate) fn from_wrapped_enum<'a, T: FromStr>(
    cx: &mut impl Context<'a>,
    wrapped_enum: Handle<JsValue>,
) -> Result<(T, Option<Handle<'a, JsValue>>), ConversionError> {
    if let Ok(s) = wrapped_enum.downcast::<JsString, _>(cx) {
        let value = s.value(cx);
        let res = match_variant_result(T::from_str(&value))?;
        Ok((res, None))
    } else if let Ok(o) = wrapped_enum.downcast::<JsObject, _>(cx) {
        let unwrapped_keys = object_keys(cx, o)?;
        for key in unwrapped_keys {
            if let Ok(res) = T::from_str(&key) {
                let value = js_result(o.get::<JsValue, _, _>(cx, key.as_str()))?;
                return Ok((res, Some(value)));
            }
        }
        Err(ConversionError::EnumVariantNotFound)
    } else {
        Err(ConversionError::BadParameter)
    }
}

pub(crate) fn wrapped_array_to_hash_set<
    'a,
    T: Eq + Hash,
    F: Fn(&mut FunctionContext, Handle<JsValue>) -> Result<T, ConversionError>,
>(
    cx: &mut FunctionContext,
    arr: Handle<JsArray>,
    convert: F,
) -> Result<HashSet<T>, ConversionError> {
    let count = arr.len(cx);
    let mut res = HashSet::new();

    for i in 0..count {
        let val = js_result(arr.get::<JsValue, _, _>(cx, i))?;
        res.insert(convert(cx, val)?);
    }

    Ok(res)
}
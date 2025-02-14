pub(crate) mod config;

use neon::prelude::*;

pub fn js_array_from_vec<'a, C, F, T>(
    cx: &mut C,
    vector: Vec<T>,
    convert: F,
) -> JsResult<'a, JsArray>
where
    C: Context<'a>,
    F: Fn(&mut C, T) -> JsResult<'a, JsValue>,
{
    let result = JsArray::new(cx, vector.len());
    for (i, value) in vector.into_iter().enumerate() {
        let js_value = convert(cx, value)?;
        result.set(cx, i as u32, js_value)?;
    }

    Ok(result)
}

/// Converts a `Vec<String>` to an js array (`string[]`).
pub fn wrap_string_array<'a>(cx: &mut impl Context<'a>, arr: Vec<String>) -> JsResult<'a, JsArray> {
    js_array_from_vec(cx, arr, |cx, s| Ok(JsString::new(cx, s).upcast()))
}

/// Converts a `Vec<u8>` into a `Uint8Array`.
pub(crate) fn uint_8_array_from_vec_u8<'a>(
    cx: &mut impl Context<'a>,
    value: Vec<u8>,
) -> NeonResult<Handle<'a, JsUint8Array>> {
    if value.len() == 0 {
        JsUint8Array::new(cx, 0)
    } else {
        // Panics on empty slice.
        JsUint8Array::from_slice(cx, &value)
    }
}

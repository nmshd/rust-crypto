pub(crate) mod config;

use neon::prelude::*;

/// Converts a `Vec<String>` to an js array (`string[]`).
pub fn wrap_string_array<'a>(cx: &mut impl Context<'a>, arr: Vec<String>) -> JsResult<'a, JsArray> {
    let result = JsArray::new(cx, arr.len());
    for (i, s) in arr.into_iter().enumerate() {
        let js_s = JsString::new(cx, s);
        result.set(cx, i as u32, js_s)?;
    }

    Ok(result)
}

/// Converts a `Vec<u8>` into a `Uint8Array`.
pub(crate) fn uint_8_array_from_vec_u8<'a>(
    cx: &mut FunctionContext<'a>,
    value: Vec<u8>,
) -> NeonResult<Handle<'a, JsUint8Array>> {
    if value.len() == 0 {
        JsUint8Array::new(cx, 0)
    } else {
        // Panics on empty slice.
        JsUint8Array::from_slice(cx, &value)
    }
}

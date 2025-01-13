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

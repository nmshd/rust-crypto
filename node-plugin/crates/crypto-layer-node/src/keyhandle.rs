use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::fromjs::error::unwrap_or_throw;
use crate::tojs::config::wrap_key_spec;
use crate::JsKeyHandle;

/// Wraps `id` function.
///
/// # Arguments
///
/// # Returns
/// * `string` - id of key
///
/// # Throws
/// * When failing to execute.
pub fn export_id(mut cx: FunctionContext) -> JsResult<JsString> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    let id = unwrap_or_throw!(cx, handle.id());
    Ok(cx.string(id))
}

/// Wraps `delete` function.
///
/// # Arguments
///
/// # Returns
/// * `undefined`
///
/// # Throws
/// * When failing to execute.
pub fn export_delete(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    unwrap_or_throw!(cx, handle.clone().delete());
    Ok(cx.undefined())
}

/// Wraps `encrypt_data` function.
///
/// # Arguments
/// * **data**: `Uint8Array`
///
/// # Returns
/// * `[Uint8Array, Uint8Array]` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_encrypt_data(mut cx: FunctionContext) -> JsResult<JsArray> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = data_js.as_slice(&mut cx);

    let (encrypted_data, iv) = unwrap_or_throw!(cx, handle.encrypt_data(data));
    let arr = cx.empty_array();
    let encrypted_data_js = JsUint8Array::from_slice(&mut cx, &encrypted_data)?;
    arr.set(&mut cx, 0, encrypted_data_js)?;
    let iv_js = if iv.len() == 0 {
        JsUint8Array::new(&mut cx, 0)?
    } else {
        JsUint8Array::from_slice(&mut cx, &iv)?
    };
    arr.set(&mut cx, 1, iv_js)?;
    Ok(arr)
}

/// Wraps `decrypt_data` function.
///
/// # Arguments
/// * **encryptedData**: `Uint8Array`
/// * **iv**: `Uint8Array`
///
/// # Returns
/// * `Uint8Array` - decrypted data on success
///
/// # Throws
/// * When failing to execute.
pub fn export_decrypt_data(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = data_js.as_slice(&mut cx).to_vec();
    let iv_js = cx.argument::<JsUint8Array>(1)?;
    let iv = if iv_js.size(&mut cx) == 0 {
        vec![]
    } else {
        Vec::from(iv_js.as_slice(&mut cx))
    };

    let decrypted_data = unwrap_or_throw!(cx, handle.decrypt_data(&data, &iv));
    Ok(JsUint8Array::from_slice(&mut cx, &decrypted_data)?)
}

/// Wraps `extract_key` function.
///
/// # Arguments
///
/// # Returns
/// * `Uint8Array` - key on success
///
/// # Throws
/// * When failing to execute.
pub fn export_extract_key(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();

    let key = unwrap_or_throw!(cx, handle.extract_key());
    Ok(JsUint8Array::from_slice(&mut cx, &key)?)
}

/// Wraps `spec` function.
///
/// # Arguments
///
/// # Returns
/// * `KeySpec` - spec of key
///
/// # Throws
pub fn export_spec(mut cx: FunctionContext) -> JsResult<JsObject> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();

    let spec = handle.spec();
    wrap_key_spec(&mut cx, spec)
}

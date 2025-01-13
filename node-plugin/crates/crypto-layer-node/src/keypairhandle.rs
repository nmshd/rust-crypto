use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::error::unwrap_or_throw;
use crate::JsKeyPairHandle;

/// Wraps `sign_data` function.
///
/// # Arguments\
/// * **data**: `Uint8Array`
///
/// # Returns
/// * `Uint8Array` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_sign_data(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let mut data_js = cx.argument::<JsUint8Array>(0)?;

    let data = data_js.as_mut_slice(&mut cx);
    let handle = handle_js.borrow();
    let signature = unwrap_or_throw!(cx, handle.sign_data(data));
    Ok(JsUint8Array::from_slice(&mut cx, &signature)?)
}

/// Wraps `verify_data` function.
///
/// # Arguments
/// * **data**: `Uint8Array`
/// * **signature**: `Uint8Array`
///
/// # Returns
/// * `boolean` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_verify_data(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let mut data_js = cx.argument::<JsUint8Array>(0)?;
    let mut signature_js = cx.argument::<JsUint8Array>(1)?;

    let data = Vec::from(data_js.as_mut_slice(&mut cx));
    let signature = signature_js.as_mut_slice(&mut cx);
    let handle = handle_js.borrow();
    let res = unwrap_or_throw!(cx, handle.verify_signature(&data, signature));
    Ok(cx.boolean(res))
}

/// Wraps `id` function.
///
/// # Arguments
///
/// # Returns
/// * `string` - id of key pair
///
/// # Throws
/// * When failing to execute.
pub fn export_id(mut cx: FunctionContext) -> JsResult<JsString> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
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
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let handle = handle_js.borrow();
    unwrap_or_throw!(cx, handle.clone().delete());
    Ok(cx.undefined())
}

/// Wraps `verify_data` function.
///
/// # Arguments
/// * **data**: `Uint8Array`
/// * **signature**: `Uint8Array`
///
/// # Returns
/// * `boolean` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_encrypt_data(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let handle = handle_js.borrow();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = data_js.as_slice(&mut cx);

    let encrypted_data = unwrap_or_throw!(cx, handle.encrypt_data(data));
    Ok(JsUint8Array::from_slice(&mut cx, &encrypted_data)?)
}

/// Wraps `decrypt_data` function.
///
/// # Arguments
/// * **encryptedData**: `Uint8Array`
///
/// # Returns
/// * `Uint8Array` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_decrypt_data(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let handle = handle_js.borrow();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = data_js.as_slice(&mut cx);

    let decrypted_data = unwrap_or_throw!(cx, handle.decrypt_data(data));
    Ok(JsUint8Array::from_slice(&mut cx, &decrypted_data)?)
}

/// Wraps `get_public_key` function.
///
/// # Arguments
///
/// # Returns
/// * `Uint8Array` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_get_public_key(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let handle = handle_js.borrow();

    let public_key = unwrap_or_throw!(cx, handle.get_public_key());
    Ok(JsUint8Array::from_slice(&mut cx, &public_key)?)
}

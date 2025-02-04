use neon::prelude::*;

use crate::error::unwrap_or_throw;
use crate::fromjs::vec_from_uint_8_array;
use crate::tojs::config::wrap_key_pair_spec;
use crate::tojs::uint_8_array_from_vec_u8;
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
    let data_js = cx.argument::<JsUint8Array>(0)?;

    let data = vec_from_uint_8_array(&mut cx, data_js);
    let handle = handle_js.borrow();

    let signature = unwrap_or_throw!(cx, handle.sign_data(&data));
    Ok(uint_8_array_from_vec_u8(&mut cx, signature)?)
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
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let signature_js = cx.argument::<JsUint8Array>(1)?;

    let data = vec_from_uint_8_array(&mut cx, data_js);
    let signature = vec_from_uint_8_array(&mut cx, signature_js);
    let handle = handle_js.borrow();
    let res = unwrap_or_throw!(cx, handle.verify_signature(&data, &signature));
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
    let data = vec_from_uint_8_array(&mut cx, data_js);

    let encrypted_data = unwrap_or_throw!(cx, handle.encrypt_data(&data));
    Ok(uint_8_array_from_vec_u8(&mut cx, encrypted_data)?)
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
    let data = vec_from_uint_8_array(&mut cx, data_js);

    let decrypted_data = unwrap_or_throw!(cx, handle.decrypt_data(&data));
    Ok(uint_8_array_from_vec_u8(&mut cx, decrypted_data)?)
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
    Ok(uint_8_array_from_vec_u8(&mut cx, public_key)?)
}

/// Wraps `extract_key` function.
///
/// # Arguments
///
/// # Returns
/// * `Uint8Array` - on success
///
/// # Throws
/// * When failing to execute.
pub fn export_extract_key(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let handle = handle_js.borrow();

    let private_key = unwrap_or_throw!(cx, handle.extract_key());
    Ok(uint_8_array_from_vec_u8(&mut cx, private_key)?)
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
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let handle = handle_js.borrow();

    let spec = handle.spec();
    wrap_key_pair_spec(&mut cx, spec)
}

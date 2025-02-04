use neon::prelude::*;

use crate::common::{arc_or_poisoned_error_deferred, spawn_promise};
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
pub fn export_sign_data(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();

    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = vec_from_uint_8_array(&mut cx, data_js);

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let signature = handle.sign_data(&data);

        deferred.settle_with(&channel, |mut cx| {
            let signature = unwrap_or_throw!(cx, signature);
            Ok(uint_8_array_from_vec_u8(&mut cx, signature)?)
        });
    })
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
pub fn export_verify_data(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let signature_js = cx.argument::<JsUint8Array>(1)?;

    let data = vec_from_uint_8_array(&mut cx, data_js);
    let signature = vec_from_uint_8_array(&mut cx, signature_js);

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let res = handle.verify_signature(&data, &signature);

        deferred.settle_with(&channel, |mut cx| {
            let res = unwrap_or_throw!(cx, res);
            Ok(cx.boolean(res))
        });
    })
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
pub fn export_id(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let id = handle.id();

        deferred.settle_with(&channel, |mut cx| {
            let id = unwrap_or_throw!(cx, id);
            Ok(cx.string(id))
        });
    })
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
pub fn export_delete(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let result = handle.clone().delete();

        deferred.settle_with(&channel, |mut cx| {
            unwrap_or_throw!(cx, result);
            Ok(cx.undefined())
        });
    })
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
pub fn export_encrypt_data(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = vec_from_uint_8_array(&mut cx, data_js);

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let encrypted_data = handle.encrypt_data(&data);

        deferred.settle_with(&channel, |mut cx| {
            let encrypted_data = unwrap_or_throw!(cx, encrypted_data);
            Ok(uint_8_array_from_vec_u8(&mut cx, encrypted_data)?)
        });
    })
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
pub fn export_decrypt_data(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = vec_from_uint_8_array(&mut cx, data_js);

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let decrypted_data = handle.decrypt_data(&data);

        deferred.settle_with(&channel, |mut cx| {
            let decrypted_data = unwrap_or_throw!(cx, decrypted_data);
            Ok(uint_8_array_from_vec_u8(&mut cx, decrypted_data)?)
        });
    })
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
pub fn export_get_public_key(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let public_key = handle.get_public_key();

        deferred.settle_with(&channel, |mut cx| {
            let public_key = unwrap_or_throw!(cx, public_key);
            Ok(uint_8_array_from_vec_u8(&mut cx, public_key)?)
        });
    })
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
pub fn export_extract_key(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let private_key = handle.extract_key();

        deferred.settle_with(&channel, |mut cx| {
            let private_key = unwrap_or_throw!(cx, private_key);
            Ok(uint_8_array_from_vec_u8(&mut cx, private_key)?)
        });
    })
}

/// Wraps `spec` function.
///
/// # Arguments
///
/// # Returns
/// * `KeySpec` - spec of key
///
/// # Throws
pub fn export_spec(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsKeyPairHandle>()?).clone();

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let spec = handle.spec();

        deferred.settle_with(&channel, move |mut cx| wrap_key_pair_spec(&mut cx, spec));
    })
}

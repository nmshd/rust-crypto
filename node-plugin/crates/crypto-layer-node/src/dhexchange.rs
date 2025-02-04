use neon::prelude::*;

use crate::common::{arc_or_poisoned_error_deferred, box_if_ok, spawn_promise};
use crate::fromjs::error::unwrap_or_throw;
use crate::fromjs::vec_from_uint_8_array;
use crate::tojs::uint_8_array_from_vec_u8;
use crate::JsDhExchange;

/// Wraps `get_public_key` function.
///
/// # Arguments
///
/// # Returns
/// * `Uint8Array` - public key for exchange
///
/// # Throws
/// * When failing to get public key.
pub fn export_get_public_key(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsDhExchange>()?).clone();

    spawn_promise(&mut cx, move |channel, deferred| {
        let handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.read());

        let public_key = handle.get_public_key();

        deferred.settle_with(&channel, |mut cx| {
            let public_key = unwrap_or_throw!(cx, public_key);
            Ok(uint_8_array_from_vec_u8(&mut cx, public_key)?)
        });
    })
}

/// Wraps `add_external` function.
///
/// # Arguments
/// * **externalKey**: `Uint8Array`
///
/// # Returns
/// * `Uint8Array` - public key for exchange
///
/// # Throws
/// * When failing to execute.
pub fn export_add_external(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsDhExchange>()?).clone();
    let raw_public_key_js = cx.argument::<JsUint8Array>(0)?;
    let raw_public_key = vec_from_uint_8_array(&mut cx, raw_public_key_js);

    spawn_promise(&mut cx, move |channel, deferred| {
        let mut handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.write());

        let new_raw_key = handle.add_external(&raw_public_key);

        deferred.settle_with(&channel, |mut cx| {
            let new_raw_key = unwrap_or_throw!(cx, new_raw_key);
            Ok(uint_8_array_from_vec_u8(&mut cx, new_raw_key)?)
        });
    })
}

/// Wraps `add_external_final` function.
///
/// # Arguments
/// * **externalKey**: `Uint8Array`
///
/// # Returns
/// * `KeyHandle` - asymmetric key resulting from exchange
///
/// # Throws
/// * When failing to execute.
pub fn export_add_external_final(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let handle_arc = (**cx.this::<JsDhExchange>()?).clone();
    let raw_public_key_js = cx.argument::<JsUint8Array>(0)?;
    let raw_public_key = vec_from_uint_8_array(&mut cx, raw_public_key_js);

    spawn_promise(&mut cx, move |channel, deferred| {
        let mut handle = arc_or_poisoned_error_deferred!(&channel, deferred, handle_arc.write());

        let key_handle = handle.add_external_final(&raw_public_key);

        deferred.settle_with(&channel, |mut cx| box_if_ok(&mut cx, key_handle));
    })
}

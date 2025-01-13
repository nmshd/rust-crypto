use std::cell::RefCell;

use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::common::Finalized;
use crate::fromjs::error::unwrap_or_throw;
use crate::{JsDhExchange, JsKeyHandle};

/// Wraps `get_public_key` function.
///
/// # Arguments
///
/// # Returns
/// * `Uint8Array` - public key for exchange
///
/// # Throws
/// * When failing to get public key.
pub fn export_get_public_key(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsDhExchange>()?;
    let handle = handle_js.borrow();

    let public_key = unwrap_or_throw!(cx, handle.get_public_key());
    Ok(JsUint8Array::from_slice(&mut cx, &public_key)?)
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
pub fn export_add_external(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let dh_exchange_js = cx.this::<JsDhExchange>()?;
    let mut dh_exchange = dh_exchange_js.borrow_mut();
    let raw_public_key_js = cx.argument::<JsUint8Array>(0)?;
    let raw_public_key = raw_public_key_js.as_slice(&cx).to_vec();

    let new_raw_key = unwrap_or_throw!(cx, dh_exchange.add_external(&raw_public_key));

    Ok(JsUint8Array::from_slice(&mut cx, &new_raw_key)?)
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
pub fn export_add_external_final(mut cx: FunctionContext) -> JsResult<JsKeyHandle> {
    let dh_exchange_js = cx.this::<JsDhExchange>()?;
    let mut dh_exchange = dh_exchange_js.borrow_mut();
    let raw_public_key_js = cx.argument::<JsUint8Array>(0)?;
    let raw_public_key = raw_public_key_js.as_slice(&cx).to_vec();

    let key_handle = unwrap_or_throw!(cx, dh_exchange.add_external_final(&raw_public_key));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_handle)),
    ))
}

use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::error::unwrap_or_throw;
use crate::fromjs;
use crate::JsKeyPairHandle;

pub fn export_sign_data(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyPairHandle>()?;
    let mut data_js = cx.argument::<JsUint8Array>(0)?;

    let data = data_js.as_mut_slice(&mut cx);
    let handle = handle_js.borrow();
    let signature = unwrap_or_throw!(cx, handle.sign_data(data));
    Ok(JsUint8Array::from_slice(&mut cx, &signature)?)
}

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

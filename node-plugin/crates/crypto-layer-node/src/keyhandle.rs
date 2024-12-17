
use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::fromjs::error::unwrap_or_throw;
use crate::JsKeyHandle;

pub fn export_id(mut cx: FunctionContext) -> JsResult<JsString> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    let id = unwrap_or_throw!(cx, handle.id());
    Ok(cx.string(id))
}

pub fn export_delete(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    unwrap_or_throw!(cx, handle.clone().delete());
    Ok(cx.undefined())
} 

pub fn export_encrypt_data(mut cx: FunctionContext) -> JsResult<JsArray> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = data_js.as_slice(&mut cx);

    let (encrypted_data, iv) = unwrap_or_throw!(cx, handle.encrypt_data(data));
    let arr = cx.empty_array();
    let encrypted_data_js = JsUint8Array::from_slice(&mut cx, &encrypted_data)?;
    arr.set(&mut cx, 0, encrypted_data_js)?;
    let iv_js = JsUint8Array::from_slice(&mut cx, &iv)?;
    arr.set(&mut cx, 1, iv_js)?;
    Ok(arr)
}

pub fn export_decrypt_data(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();
    let data_js = cx.argument::<JsUint8Array>(0)?;
    let data = data_js.as_slice(&mut cx).to_vec();
    let iv_js = cx.argument::<JsUint8Array>(1)?;
    let iv = iv_js.as_slice(&mut cx);

    let decrypted_data = unwrap_or_throw!(cx, handle.decrypt_data(&data, iv));
    Ok(JsUint8Array::from_slice(&mut cx, &decrypted_data)?)
}

pub fn export_extract_key(mut cx: FunctionContext) -> JsResult<JsUint8Array> {
    let handle_js = cx.this::<JsKeyHandle>()?;
    let handle = handle_js.borrow();

    let key = unwrap_or_throw!(cx, handle.extract_key());
    Ok(JsUint8Array::from_slice(&mut cx, &key)?)
}

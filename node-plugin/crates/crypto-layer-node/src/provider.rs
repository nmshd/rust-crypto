use std::cell::RefCell;

use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::common::Finalized;
use crate::fromjs::error::unwrap_or_throw;
use crate::{from_wrapped_key_pair_spec, from_wrapped_key_spec};
use crate::{JsKeyHandle, JsKeyPairHandle, JsProvider};

pub fn export_create_key(mut cx: FunctionContext) -> JsResult<JsKeyHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let spec_js = cx.argument::<JsObject>(0)?;

    let spec = unwrap_or_throw!(cx, from_wrapped_key_spec(&mut cx, spec_js));

    let mut provider = provider_js.borrow_mut();
    let key_handle = unwrap_or_throw!(cx, provider.create_key(spec));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_handle)),
    ))
}

pub fn export_create_key_pair(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let spec_js = cx.argument::<JsObject>(0)?;

    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));

    let mut provider = provider_js.borrow_mut();
    let key_pair_handle = unwrap_or_throw!(cx, provider.create_key_pair(spec));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_pair_handle)),
    ))
}

pub fn export_provider_name(mut cx: FunctionContext) -> JsResult<JsString> {
    let provider_js = cx.this::<JsProvider>()?;
    let provider = provider_js.borrow();
    Ok(cx.string(provider.provider_name()))
}


pub fn export_load_key(mut cx: FunctionContext) -> JsResult<JsKeyHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let id_js = cx.argument::<JsString>(0)?;
    let id = id_js.value(&mut cx);

    
    let key_handle = unwrap_or_throw!(cx, provider.load_key(id));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_handle)),
    ))
}

pub fn export_load_key_pair(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let id_js = cx.argument::<JsString>(0)?;
    let id = id_js.value(&mut cx);

    
    let key_pair_handle = unwrap_or_throw!(cx, provider.load_key_pair(id));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_pair_handle)),
    ))
}

pub fn export_import_key(mut cx: FunctionContext) -> JsResult<JsKeyHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_spec(&mut cx, spec_js));
    let raw_key_js = cx.argument::<JsUint8Array>(1)?;
    let raw_key = raw_key_js.as_slice(&cx).to_vec();
   
    let key_handle = unwrap_or_throw!(cx, provider.import_key(spec, &raw_key));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_handle)),
    ))
}

pub fn export_import_key_pair(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));
    let raw_public_key_js = cx.argument::<JsUint8Array>(1)?;
    let raw_public_key = raw_public_key_js.as_slice(&cx).to_vec();
    let raw_private_key_js = cx.argument::<JsUint8Array>(2)?;
    let raw_private_key = raw_private_key_js.as_slice(&cx).to_vec();
   
    let key_pair_handle = unwrap_or_throw!(cx, provider.import_key_pair(spec, &raw_public_key, &raw_private_key));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_pair_handle)),
    ))
}

pub fn export_import_public_key(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));
    let raw_public_key_js = cx.argument::<JsUint8Array>(1)?;
    let raw_public_key = raw_public_key_js.as_slice(&cx).to_vec();
   
    let key_pair_handle = unwrap_or_throw!(cx, provider.import_public_key(spec, &raw_public_key));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_pair_handle)),
    ))
}
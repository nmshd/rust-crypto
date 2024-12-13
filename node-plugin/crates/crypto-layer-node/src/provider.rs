use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;

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

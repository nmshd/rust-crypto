use std::cell::RefCell;
use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;

use crate::dhexchange::WrappedDHExchange;
use crate::fromjs::error::unwrap_or_throw;
use crate::keyhandle::WrappedKeyHandle;
use crate::keypairhandle::WrappedKeyPairHandle;
use crate::{from_wrapped_key_pair_spec, from_wrapped_key_spec};
use crate::{JsKeyHandle, JsKeyPairHandle, JsProvider};

pub(crate) struct WrappedProvider {
    provider: Provider,
}

impl WrappedProvider {
    pub(crate) fn new(provider: Provider) -> Self {
        Self { provider }
    }
}

impl Deref for WrappedProvider {
    type Target = Provider;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}

impl DerefMut for WrappedProvider {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.provider
    }
}

impl Finalize for WrappedProvider {}

pub fn export_create_key(mut cx: FunctionContext) -> JsResult<JsKeyHandle> {
    let provider_js = cx.argument::<JsProvider>(0)?;
    let spec_js = cx.argument::<JsObject>(1)?;

    let spec = unwrap_or_throw!(cx, from_wrapped_key_spec(&mut cx, spec_js));

    let mut provider = provider_js.borrow_mut();
    let key_handle = unwrap_or_throw!(cx, provider.create_key(spec));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(WrappedKeyHandle::new(key_handle)),
    ))
}

pub fn export_create_key_pair(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.argument::<JsProvider>(0)?;
    let spec_js = cx.argument::<JsObject>(1)?;

    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));

    let mut provider = provider_js.borrow_mut();
    let key_pair_handle = unwrap_or_throw!(cx, provider.create_key_pair(spec));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(WrappedKeyPairHandle::new(key_pair_handle)),
    ))
}

pub fn export_provider_name(mut cx: FunctionContext) -> JsResult<JsString> {
    let provider_js = cx.argument::<JsProvider>(0)?;
    let provider = provider_js.borrow();
    Ok(cx.string(provider.provider_name()))
}

use std::cell::RefCell;

use neon::prelude::*;

use crate::common::Finalized;
use crate::fromjs::error::unwrap_or_throw;
use crate::fromjs::vec_from_uint_8_array;
use crate::tojs::config::wrap_provider_config;
use crate::{from_wrapped_key_pair_spec, from_wrapped_key_spec};
use crate::{JsDhExchange, JsKeyHandle, JsKeyPairHandle, JsProvider};

/// Wraps `create_key` function.
///
/// # Arguments
/// * **spec**: `KeySpec`
///
/// # Returns
/// * `{}` - bare key handle on success
///
/// # Throws
/// * When one of the inputs is incorrect.
/// * When failing to generate the key.
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

/// Wraps `create_key_pair` function.
///
/// # Arguments
/// * **spec**: `KeyPairSpec`
///
/// # Returns
/// * `{}` - bare key pair handle on success
///
/// # Throws
/// * When one of the inputs is incorrect.
/// * When failing to generate the key pair.
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

/// Wraps `provider_name` function.
///
/// # Arguments
///
/// # Returns
/// * `string` - provider name
///
/// # Throws
pub fn export_provider_name(mut cx: FunctionContext) -> JsResult<JsString> {
    let provider_js = cx.this::<JsProvider>()?;
    let provider = provider_js.borrow();
    Ok(cx.string(provider.provider_name()))
}

/// Wraps `load_key` function.
///
/// # Arguments
/// * **id**: `string`
///
/// # Returns
/// * `{}` - bare key handle on success
///
/// # Throws
/// * When failing to load the key.
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

/// Wraps `load_key_pair` function.
///
/// # Arguments
/// * **id**: `string`
///
/// # Returns
/// * `{}` - bare key pair handle on success
///
/// # Throws
/// * When failing to load the key pair.
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

/// Wraps `import_key` function.
///
/// # Arguments
/// * **spec**: `KeySpec`
/// * **key**: `Uint8Array`
///
/// # Returns
/// * `{}` - bare key handle on success
///
/// # Throws
/// * When one of the inputs is incorrect.
/// * When failing to import the key.
pub fn export_import_key(mut cx: FunctionContext) -> JsResult<JsKeyHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_spec(&mut cx, spec_js));
    let raw_key_js = cx.argument::<JsUint8Array>(1)?;
    let raw_key = vec_from_uint_8_array(&mut cx, raw_key_js);

    let key_handle = unwrap_or_throw!(cx, provider.import_key(spec, &raw_key));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_handle)),
    ))
}

/// Wraps `import_key_pair` function.
///
/// # Arguments
/// * **spec**: `KeyPairSpec`
/// * **publicKey**: `Uint8Array`
/// * **privateKey**: `Uint8Array`
///
/// # Returns
/// * `{}` - bare key pair handle on success
///
/// # Throws
/// * When one of the inputs is incorrect.
/// * When failing to import the key pair.
pub fn export_import_key_pair(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));
    let raw_public_key_js = cx.argument::<JsUint8Array>(1)?;
    let raw_public_key = vec_from_uint_8_array(&mut cx, raw_public_key_js);
    let raw_private_key_js = cx.argument::<JsUint8Array>(2)?;
    let raw_private_key = vec_from_uint_8_array(&mut cx, raw_private_key_js);

    let key_pair_handle = unwrap_or_throw!(
        cx,
        provider.import_key_pair(spec, &raw_public_key, &raw_private_key)
    );

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_pair_handle)),
    ))
}

/// Wraps `import_public_key` function.
///
/// # Arguments
/// * **spec**: `KeyPairSpec`
/// * **publicKey**: `Uint8Array`
///
/// # Returns
/// * `{}` - bare key pair handle on success
///
/// # Throws
/// * When one of the inputs is incorrect.
/// * When failing to import the public key.
pub fn export_import_public_key(mut cx: FunctionContext) -> JsResult<JsKeyPairHandle> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));
    let raw_public_key_js = cx.argument::<JsUint8Array>(1)?;
    let raw_public_key = vec_from_uint_8_array(&mut cx, raw_public_key_js);

    let key_pair_handle = unwrap_or_throw!(cx, provider.import_public_key(spec, &raw_public_key));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(key_pair_handle)),
    ))
}

/// Wraps `get_capabilities` function.
///
/// # Arguments
///
/// # Returns
/// * `ProviderConfig` - config on success
/// * `undefined` - none on failure
///
/// # Throws
/// * When failing to wrap provider config.
pub fn export_get_capabilities(mut cx: FunctionContext) -> JsResult<JsValue> {
    let provider_js = cx.this::<JsProvider>()?;
    let provider = provider_js.borrow();
    if let Some(capabilities) = provider.get_capabilities() {
        Ok(wrap_provider_config(&mut cx, capabilities)?.upcast())
    } else {
        Ok(cx.undefined().upcast())
    }
}

/// Wraps `ephemeral_dh_exchange` function.
///
/// # Arguments
/// * **spec**: `KeyPairSpec`
///
/// # Returns
/// * `{}` - bare dh exchange
///
/// # Throws
/// * When one of the inputs is incorrect.
/// * When failing to start the dh exchange.
pub fn export_start_ephemeral_dh_exchange(mut cx: FunctionContext) -> JsResult<JsDhExchange> {
    let provider_js = cx.this::<JsProvider>()?;
    let mut provider = provider_js.borrow_mut();
    let spec_js = cx.argument::<JsObject>(0)?;
    let spec = unwrap_or_throw!(cx, from_wrapped_key_pair_spec(&mut cx, spec_js));

    let dh_exchange = unwrap_or_throw!(cx, provider.start_ephemeral_dh_exchange(spec));

    Ok(JsBox::new(
        &mut cx,
        RefCell::new(Finalized::new(dh_exchange)),
    ))
}

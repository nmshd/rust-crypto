use std::sync::{Arc, RwLock};

use color_eyre;
use crypto_layer::prelude::*;
use neon::prelude::*;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    fmt,
    fmt::format::FmtSpan,
};

pub(crate) mod common;
pub(crate) mod dhexchange;
pub(crate) mod fromjs;
pub(crate) mod keyhandle;
pub(crate) mod keypairhandle;
pub(crate) mod provider;
pub(crate) mod tojs;

use crate::common::{box_if_ok, spawn_promise, Finalized};
use crate::fromjs::error::unwrap_or_throw;
use fromjs::config::*;
use fromjs::*;
use tojs::config::wrap_provider_config;
use tojs::*;

type JsKeyHandle = JsBox<Arc<RwLock<Finalized<KeyHandle>>>>;
type JsKeyPairHandle = JsBox<Arc<RwLock<Finalized<KeyPairHandle>>>>;
type JsProvider = JsBox<Arc<RwLock<Finalized<Provider>>>>;
type JsDhExchange = JsBox<Arc<RwLock<Finalized<DHExchange>>>>;

/// Wraps `get_all_providers` function.
///
/// # Arguments
///
/// # Returns
/// * `string[]`
fn export_get_all_providers(mut cx: FunctionContext) -> JsResult<JsPromise> {
    spawn_promise(&mut cx, move |channel, deferred| {
        let providers = get_all_providers();
        deferred.settle_with(&channel, |mut cx| wrap_string_array(&mut cx, providers));
    })
}

/// Wraps `create_provider` function.
///
/// # Arguments
/// * **config**: `ProviderConfig`
/// * **impl_config**: `ProviderImplConfig`
///
/// # Returns
/// * `{}` - bare provider on success
/// * `undefined` - None on failure
///
/// # Throws
/// * When one of the inputs is incorrect.
#[tracing::instrument(level = "trace", skip(cx))]
fn export_create_provider(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let config_js = cx.argument::<JsObject>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    let config = unwrap_or_throw!(cx, from_wrapped_provider_config(&mut cx, config_js));
    let impl_config = unwrap_or_throw!(
        cx,
        from_wrapped_provider_impl_config(&mut cx, impl_config_js)
    );

    spawn_promise(&mut cx, move |channel, deferred| {
        match create_provider(&config, impl_config.clone()) {
            Some(prov) => deferred.settle_with(&channel, |mut cx| box_if_ok(&mut cx, Ok(prov))),
            None => deferred.settle_with(&channel, |mut cx| Ok(cx.undefined())),
        };
    })
}

/// Wraps `create_provider_from_name` function.
///
/// # Arguments
/// * **name**: `string`
/// * **impl_config**: `ProviderImplConfig`
///
/// # Returns
/// * `{}` - bare provider on success
/// * `undefined` - None on failure
///
/// # Throws
/// * When one of the inputs is incorrect.
#[tracing::instrument(level = "trace", skip(cx))]
fn export_create_provider_from_name(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let name_js = cx.argument::<JsString>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    let name = name_js.value(&mut cx);
    let impl_config = unwrap_or_throw!(
        cx,
        from_wrapped_provider_impl_config(&mut cx, impl_config_js)
    );

    spawn_promise(&mut cx, move |channel, deferred| {
        match create_provider_from_name(&name, impl_config.clone()) {
            Some(prov) => deferred.settle_with(&channel, |mut cx| box_if_ok(&mut cx, Ok(prov))),
            None => deferred.settle_with(&channel, |mut cx| Ok(cx.undefined())),
        };
    })
}

/// Wraps `get_provider_capabilities` function.
///
/// # Arguments
/// * **impl_config**: `ProviderImplConfig`
///
/// # Returns
/// * `[string, ProviderConfig][]` - list of providers and their capabilities that are initializable.
///
/// # Throws
fn export_get_provider_capabilities(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let impl_config_js = cx.argument::<JsObject>(0)?;
    let impl_config = unwrap_or_throw!(
        cx,
        from_wrapped_provider_impl_config(&mut cx, impl_config_js)
    );

    spawn_promise(&mut cx, move |channel, deferred| {
        let provider_caps_list = get_provider_capabilities(impl_config.clone());
        deferred.settle_with(&channel, |mut cx| {
            js_array_from_vec(&mut cx, provider_caps_list, |cx, value| {
                let name = JsString::new(cx, value.0);
                let caps = wrap_provider_config(cx, value.1)?;

                let tuple = JsArray::new(cx, 2);
                tuple.set(cx, 0, name)?;
                tuple.set(cx, 1, caps)?;

                Ok(tuple.upcast())
            })
        });
    })
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    fmt()
        .with_line_number(true)
        .with_max_level(LevelFilter::DEBUG)
        .with_span_events(FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    color_eyre::install().unwrap();

    let load_function_span = tracing::trace_span!("Loading module functions.").entered();

    // factory
    cx.export_function("getAllProviders", export_get_all_providers)?;
    cx.export_function("createBareProvider", export_create_provider)?;
    cx.export_function(
        "createBareProviderFromName",
        export_create_provider_from_name,
    )?;
    cx.export_function("getProviderCapabilities", export_get_provider_capabilities)?;

    // provider
    cx.export_function("providerName", crate::provider::export_provider_name)?;
    cx.export_function("createBareKey", crate::provider::export_create_key)?;
    cx.export_function("createBareKeyPair", crate::provider::export_create_key_pair)?;
    cx.export_function("loadBareKey", crate::provider::export_load_key)?;
    cx.export_function("loadBareKeyPair", crate::provider::export_load_key_pair)?;
    cx.export_function("importBareKey", crate::provider::export_import_key)?;
    cx.export_function("importBareKeyPair", crate::provider::export_import_key_pair)?;
    cx.export_function(
        "importBarePublicKey",
        crate::provider::export_import_public_key,
    )?;
    cx.export_function("getCapabilities", crate::provider::export_get_capabilities)?;
    cx.export_function(
        "startEphemeralDhExchange",
        crate::provider::export_start_ephemeral_dh_exchange,
    )?;

    // key pair handle
    cx.export_function("signData", crate::keypairhandle::export_sign_data)?;
    cx.export_function("verifySignature", crate::keypairhandle::export_verify_data)?;
    cx.export_function("idForKeyPair", crate::keypairhandle::export_id)?;
    cx.export_function("deleteForKeyPair", crate::keypairhandle::export_delete)?;
    cx.export_function("getPublicKey", crate::keypairhandle::export_get_public_key)?;
    cx.export_function(
        "extractKeyForKeyPairHandle",
        crate::keypairhandle::export_extract_key,
    )?;
    cx.export_function(
        "encryptDataForKeyPairHandle",
        crate::keypairhandle::export_encrypt_data,
    )?;
    cx.export_function(
        "decryptDataForKeyPairHandle",
        crate::keypairhandle::export_decrypt_data,
    )?;
    cx.export_function("specForKeyPairHandle", crate::keypairhandle::export_spec)?;

    // key handle
    cx.export_function("idForKeyHandle", crate::keyhandle::export_id)?;
    cx.export_function("deleteForKeyHandle", crate::keyhandle::export_delete)?;
    cx.export_function(
        "extractKeyForKeyHandle",
        crate::keyhandle::export_extract_key,
    )?;
    cx.export_function(
        "encryptDataForKeyHandle",
        crate::keyhandle::export_encrypt_data,
    )?;
    cx.export_function(
        "decryptDataForKeyHandle",
        crate::keyhandle::export_decrypt_data,
    )?;
    cx.export_function("specForKeyHandle", crate::keyhandle::export_spec)?;

    // dh exchange
    cx.export_function(
        "getPublicKeyForDHExchange",
        crate::dhexchange::export_get_public_key,
    )?;
    cx.export_function(
        "addExternalForDHExchange",
        crate::dhexchange::export_add_external,
    )?;
    cx.export_function(
        "addExternalFinalForDHExchange",
        crate::dhexchange::export_add_external_final,
    )?;

    load_function_span.exit();
    tracing::trace!("crypto-layer loaded.");

    Ok(())
}

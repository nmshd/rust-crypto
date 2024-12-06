use std::cell::RefCell;

use neon::prelude::*;

use crypto_layer::prelude::*;

pub(crate) mod common;
pub(crate) mod dhexchange;
pub(crate) mod fromjs;
pub(crate) mod keyhandle;
pub(crate) mod keypairhandle;
pub(crate) mod provider;
pub(crate) mod tojs;

use crate::common::Finalized;
use crate::fromjs::error::unwrap_or_throw;
use fromjs::config::*;
use fromjs::*;
use tojs::*;

type JsKeyHandle = JsBox<RefCell<Finalized<KeyHandle>>>;
type JsKeyPairHandle = JsBox<RefCell<Finalized<KeyPairHandle>>>;
type JsProvider = JsBox<RefCell<Finalized<Provider>>>;
type JsDhExchange = JsBox<RefCell<Finalized<DHExchange>>>;

fn export_get_all_providers(mut cx: FunctionContext) -> JsResult<JsArray> {
    wrap_string_array(&mut cx, get_all_providers())
}

fn export_create_provider(mut cx: FunctionContext) -> JsResult<JsValue> {
    let config_js = cx.argument::<JsObject>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    let config = unwrap_or_throw!(cx, from_wrapped_provider_config(&mut cx, config_js));
    let impl_config = unwrap_or_throw!(
        cx,
        from_wrapped_provider_impl_config(&mut cx, impl_config_js)
    );

    match create_provider(config, impl_config) {
        Some(prov) => Ok(cx.boxed(RefCell::new(Finalized::new(prov))).upcast()),
        None => Ok(cx.undefined().upcast()),
    }
}

fn export_create_provider_from_name(mut cx: FunctionContext) -> JsResult<JsValue> {
    let name_js = cx.argument::<JsString>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    let name = name_js.value(&mut cx);
    let impl_config = unwrap_or_throw!(
        cx,
        from_wrapped_provider_impl_config(&mut cx, impl_config_js)
    );

    match create_provider_from_name(name, impl_config) {
        Some(prov) => Ok(cx.boxed(RefCell::new(Finalized::new(prov))).upcast()),
        None => Ok(cx.undefined().upcast()),
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("getAllProviders", export_get_all_providers)?;
    cx.export_function("createProvider", export_create_provider)?;
    cx.export_function("createProviderFromName", export_create_provider_from_name)?;
    cx.export_function("providerName", crate::provider::export_provider_name)?;
    cx.export_function("createKey", crate::provider::export_create_key)?;
    cx.export_function("createKeyPair", crate::provider::export_create_key_pair)?;
    Ok(())
}

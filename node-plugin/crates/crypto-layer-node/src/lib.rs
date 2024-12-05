use std::cell::RefCell;

use neon::prelude::*;

use crypto_layer::prelude::*;

pub(crate) mod dhexchange;
pub(crate) mod fromjs;
pub(crate) mod keyhandle;
pub(crate) mod keypairhandle;
pub(crate) mod provider;
pub(crate) mod tojs;

use crate::provider::WrappedProvider;
use fromjs::config::*;
use fromjs::*;
use tojs::*;

type KeyHandleJs = JsBox<RefCell<KeyHandle>>;
type KeyPairHandleJs = JsBox<RefCell<KeyPairHandle>>;
type ProviderJs = JsBox<RefCell<Provider>>;
type DhExchangeJs = JsBox<RefCell<DHExchange>>;

fn export_get_all_providers(mut cx: FunctionContext) -> JsResult<JsArray> {
    wrap_string_array(&mut cx, get_all_providers())
}

fn export_create_provider(mut cx: FunctionContext) -> JsResult<JsValue> {
    let config_js = cx.argument::<JsObject>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    let config = match from_wrapped_provider_config(&mut cx, config_js) {
        Ok(res) => res,
        Err(e) => e.js_throw(&mut cx)?,
    };
    let impl_config = match from_wrapped_provider_impl_config(&mut cx, impl_config_js) {
        Ok(res) => res,
        Err(e) => e.js_throw(&mut cx)?,
    };

    match create_provider(config, impl_config) {
        Some(prov) => Ok(cx.boxed(RefCell::new(WrappedProvider::new(prov))).upcast()),
        None => Ok(cx.undefined().upcast()),
    }
}

fn export_create_provider_from_name(mut cx: FunctionContext) -> JsResult<JsValue> {
    let name_js = cx.argument::<JsString>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    let name = name_js.value(&mut cx);
    let impl_config = match from_wrapped_provider_impl_config(&mut cx, impl_config_js) {
        Ok(res) => res,
        Err(e) => e.js_throw(&mut cx)?,
    };

    match create_provider_from_name(name, impl_config) {
        Some(prov) => Ok(cx.boxed(RefCell::new(WrappedProvider::new(prov))).upcast()),
        None => Ok(cx.undefined().upcast()),
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("getAllProviders", export_get_all_providers)?;
    cx.export_function("createProvider", export_create_provider)?;
    cx.export_function("createProviderFromName", export_create_provider_from_name)?;
    Ok(())
}

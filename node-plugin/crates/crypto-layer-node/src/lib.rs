use std::cell::RefCell;

use neon::prelude::*;

use crypto_layer::prelude::*;

pub(crate) mod dhexchange;
pub(crate) mod fromjs;
pub(crate) mod keyhandle;
pub(crate) mod keypairhandle;
pub(crate) mod provider;
pub(crate) mod tojs;

use fromjs::*;
use tojs::*;

type KeyHandleJs = JsBox<RefCell<KeyHandle>>;
type KeyPairHandleJs = JsBox<RefCell<KeyPairHandle>>;
type ProviderJs = JsBox<RefCell<Provider>>;
type DhExchangeJs = JsBox<RefCell<DHExchange>>;

fn export_get_all_providers(mut cx: FunctionContext) -> JsResult<JsArray> {
    wrap_string_array(&mut cx, get_all_providers())
}

fn export_create_provider(mut cx: FunctionContext) -> JsResult<JsBox<Provider>> {
    let config_js = cx.argument::<JsObject>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

    /* let provider = cx.empty_object(); */

    todo!()
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("getAllProviders", export_get_all_providers)?;
    Ok(())
}

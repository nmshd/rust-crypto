use neon::prelude::*;

use crypto_layer::prelude::*;

fn wrap_string<'a>(cx: &mut impl Context<'a>, s: String) -> Handle<'a, JsString> {
    JsString::new(cx, s)
}

fn wrap_string_array<'a>(cx: &mut impl Context<'a>, arr: Vec<String>) -> JsResult<'a, JsArray> {
    let result = JsArray::new(cx, arr.len());
    for ( i, s) in arr.into_iter().enumerate() {
        let js_s = wrap_string(cx,s);
        result.set(cx, i as u32, js_s)?;
    }

    Ok(result)
}

fn export_get_all_providers(mut cx: FunctionContext) -> JsResult<JsArray> {
    wrap_string_array(&mut cx, get_all_providers())
}

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("hello node"))
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("getAllProviders", export_get_all_providers)?;
    Ok(())
}

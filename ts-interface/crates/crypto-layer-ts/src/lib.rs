use neon::prelude::*;

use crypto_layer::prelude::*;

fn wrap_string_array<'a>(cx: &mut impl Context<'a>, arr: Vec<String>) -> JsResult<'a, JsArray> {
    let result = JsArray::new(cx, arr.len());
    for ( i, s) in arr.into_iter().enumerate() {
        let js_s = JsString::new(cx, s);
        result.set(cx, i as u32, js_s)?;
    }

    Ok(result)
}

fn export_get_all_providers(mut cx: FunctionContext) -> JsResult<JsArray> {
    wrap_string_array(&mut cx, get_all_providers())
}

fn from_wrapped_security_level(cx: &mut impl Context<'a>, wrapped_security_level: Handle<JsString>) -> SecurityLevel {
    let value = wrapped_security_level.value(cx);
    match value.as_str() {
        "Hardware" => SecurityLevel::Hardware,
        "Software" => SecurityLevel::Software,
        "Network" => SecurityLevel::Network,
        "Unsafe" => SecurityLevel::Unsafe,
        _ => SecurityLevel::Unsafe
    }
}

fn from_wrapped_cipher(cx: &mut impl Context<'a>, wrapped_cipher: Handle<JsString>) -> Cipher {
    todo!()
}

fn from_wra

fn export_create_provider(mut cx: FunctionContext) -> JsResult<JsObject> {
    let config_js = cx.argument::<JsObject>(0)?;
    let impl_config_js = cx.argument::<JsObject>(1)?;

   

    let provider = cx.empty_object();


}


#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("getAllProviders", export_get_all_providers)?;
    Ok(())
}

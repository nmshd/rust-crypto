use crypto_layer::prelude::*;
use neon::prelude::*;

use super::wrap_string_array;

/// Converts `ProviderConfig` to TS type definition defined in `crypto-layer-ts-types` package.
pub fn wrap_provider_config<'a>(
    cx: &mut FunctionContext<'a>,
    config: ProviderConfig,
) -> JsResult<'a, JsObject> {
    let max_security_level_str: &'static str = config.max_security_level.into();
    let min_security_level_str: &'static str = config.min_security_level.into();
    let ciphers: Vec<String> = config
        .supported_ciphers
        .iter()
        .map(|e| {
            let cipher: &'static str = e.into();
            cipher.to_owned()
        })
        .collect();
    let hashes: Vec<String> = config
        .supported_hashes
        .iter()
        .map(|e| {
            let string: &'static str = e.into();
            string.to_owned()
        })
        .collect();
    let asym_specs: Vec<String> = config
        .supported_asym_spec
        .iter()
        .map(|e| {
            let string: &'static str = e.into();
            string.to_owned()
        })
        .collect();

    let max_security_level_js_str = cx.string(max_security_level_str);
    let min_security_level_js_str = cx.string(min_security_level_str);
    let ciphers_js = wrap_string_array(cx, ciphers)?;
    let hashes_js = wrap_string_array(cx, hashes)?;
    let asym_specs_js = wrap_string_array(cx, asym_specs)?;

    let obj = cx.empty_object();
    obj.set(cx, "max_security_level", max_security_level_js_str)?;
    obj.set(cx, "min_security_level", min_security_level_js_str)?;
    obj.set(cx, "supported_ciphers", ciphers_js)?;
    obj.set(cx, "supported_hashes", hashes_js)?;
    obj.set(cx, "supported_asym_spec", asym_specs_js)?;

    Ok(obj)
}

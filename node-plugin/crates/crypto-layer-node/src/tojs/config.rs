use crypto_layer::prelude::*;
use neon::prelude::*;

use super::wrap_string_array;

/// Inserts into a JsObject an enum as a JsString.
///
/// * `cx` - Neon Context
/// * `obj` - JsObject
/// * `insert` - An enum that implements the [strum::IntoStaticStr] trait.
///
/// `insert` may have a dot, which results in insert being split and only the child being used as name.
macro_rules! insert_as_js_str_into_obj {
    ($cx:ident, $obj:ident, $insert:expr) => {
        let insert_str: &'static str = $insert.into();
        let insert_js = $cx.string(insert_str);
        let insert_var_name = stringify!($insert);
        let insert_var_name_short = match insert_var_name.split(".").last() {
            Some(name) => name,
            None => {
                $cx.throw_error(format!("Failed writing {} to obj", insert_var_name))?;
                unreachable!();
            }
        };
        $obj.set($cx, insert_var_name_short, insert_js)?;
    };
}

/// Converts `ProviderConfig` to TS type definition defined in `crypto-layer-ts-types` package.
pub fn wrap_provider_config<'a>(
    cx: &mut FunctionContext<'a>,
    config: ProviderConfig,
) -> JsResult<'a, JsObject> {
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

    let ciphers_js = wrap_string_array(cx, ciphers)?;
    let hashes_js = wrap_string_array(cx, hashes)?;
    let asym_specs_js = wrap_string_array(cx, asym_specs)?;

    let obj = cx.empty_object();
    insert_as_js_str_into_obj!(cx, obj, config.max_security_level);
    insert_as_js_str_into_obj!(cx, obj, config.max_security_level);
    obj.set(cx, "supported_ciphers", ciphers_js)?;
    obj.set(cx, "supported_hashes", hashes_js)?;
    obj.set(cx, "supported_asym_spec", asym_specs_js)?;

    Ok(obj)
}

pub fn wrap_key_spec<'a>(cx: &mut FunctionContext<'a>, spec: KeySpec) -> JsResult<'a, JsObject> {
    let obj = cx.empty_object();

    insert_as_js_str_into_obj!(cx, obj, spec.cipher);
    insert_as_js_str_into_obj!(cx, obj, spec.signing_hash);
    let ephemeral_js = cx.boolean(spec.ephemeral);
    obj.set(cx, "ephemeral", ephemeral_js)?;

    Ok(obj)
}

pub fn wrap_key_pair_spec<'a>(
    cx: &mut FunctionContext<'a>,
    spec: KeyPairSpec,
) -> JsResult<'a, JsObject> {
    let obj = cx.empty_object();

    insert_as_js_str_into_obj!(cx, obj, spec.asym_spec);
    insert_as_js_str_into_obj!(cx, obj, spec.signing_hash);
    let ephemeral_js = cx.boolean(spec.ephemeral);
    obj.set(cx, "ephemeral", ephemeral_js)?;
    if let Some(cipher) = spec.cipher {
        insert_as_js_str_into_obj!(cx, obj, cipher);
    } else {
        let null_js = cx.null();
        obj.set(cx, "cipher", null_js)?;
    }

    Ok(obj)
}

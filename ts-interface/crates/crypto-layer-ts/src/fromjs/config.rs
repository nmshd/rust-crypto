use crypto_layer::prelude::*;
use neon::prelude::*;
use std::str::FromStr;

use super::encryption::{from_wrapped_asymm_spec, from_wrapped_cipher};
use super::error::{js_result, match_variant_result, ConversionError};
use super::hashes::from_wrapped_crypto_hash;
use super::wrapped_array_to_hash_set;

pub fn from_wrapped_security_level<'a>(
    cx: &mut impl Context<'a>,
    wrapped_security_level: Handle<JsString>,
) -> Result<SecurityLevel, ConversionError> {
    let value = wrapped_security_level.value(cx);
    match_variant_result(SecurityLevel::from_str(&value))
}

pub fn from_wrapped_provider_config<'a>(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<ProviderConfig, ConversionError> {
    let max_security_level_string =
        js_result(wrapped.get::<JsString, _, _>(cx, "max_security_level"))?;
    let min_security_level_string =
        js_result(wrapped.get::<JsString, _, _>(cx, "min_security_level"))?;
    let supported_hashes_arr = js_result(wrapped.get::<JsArray, _, _>(cx, "supported_hashes"))?;
    let supported_ciphers_arr = js_result(wrapped.get::<JsArray, _, _>(cx, "supported_ciphers"))?;
    let supported_asym_spec_arr = js_result(wrapped.get::<JsArray, _, _>(cx, "supported_ciphers"))?;

    Ok(ProviderConfig {
        max_security_level: from_wrapped_security_level(cx, max_security_level_string)?,
        min_security_level: from_wrapped_security_level(cx, min_security_level_string)?,
        supported_hashes: wrapped_array_to_hash_set(
            cx,
            supported_hashes_arr,
            from_wrapped_crypto_hash,
        )?,
        supported_ciphers: wrapped_array_to_hash_set(
            cx,
            supported_ciphers_arr,
            from_wrapped_cipher,
        )?,
        supported_asym_spec: wrapped_array_to_hash_set(
            cx,
            supported_asym_spec_arr,
            from_wrapped_asymm_spec,
        )?,
    })
}

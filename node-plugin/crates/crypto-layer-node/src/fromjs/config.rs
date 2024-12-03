use crypto_layer::common::config::AdditionalConfigDiscriminants;
use crypto_layer::prelude::*;

use neon::prelude::*;
use std::str::FromStr;

use super::error::{js_result, match_variant_result, missing_enum_values, ConversionError};
use super::{from_wrapped_enum, from_wrapped_simple_enum, object_keys, wrapped_array_to_hash_set};
use crate::KeyHandleJs;

pub fn from_wrapped_provider_config<'a>(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<ProviderConfig, ConversionError> {
    let max_security_level_string =
        js_result(wrapped.get::<JsValue, _, _>(cx, "max_security_level"))?;
    let min_security_level_string =
        js_result(wrapped.get::<JsValue, _, _>(cx, "min_security_level"))?;
    let supported_hashes_arr = js_result(wrapped.get::<JsArray, _, _>(cx, "supported_hashes"))?;
    let supported_ciphers_arr = js_result(wrapped.get::<JsArray, _, _>(cx, "supported_ciphers"))?;
    let supported_asym_spec_arr = js_result(wrapped.get::<JsArray, _, _>(cx, "supported_ciphers"))?;

    Ok(ProviderConfig {
        max_security_level: from_wrapped_simple_enum(cx, max_security_level_string)?,
        min_security_level: from_wrapped_simple_enum(cx, min_security_level_string)?,
        supported_hashes: wrapped_array_to_hash_set(
            cx,
            supported_hashes_arr,
            from_wrapped_simple_enum,
        )?,
        supported_ciphers: wrapped_array_to_hash_set(
            cx,
            supported_ciphers_arr,
            from_wrapped_simple_enum,
        )?,
        supported_asym_spec: wrapped_array_to_hash_set(
            cx,
            supported_asym_spec_arr,
            from_wrapped_simple_enum,
        )?,
    })
}

pub fn from_wrapped_provider_impl_config<'a>(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<ProviderImplConfig, ConversionError> {
    let additional_config: Handle<'_, JsArray> = js_result(wrapped.get(cx, "additional_config"))?;

    todo!()
}

pub fn from_wrapped_additional_config<'a>(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<AdditionalConfig, ConversionError> {
    let (additional_config, obj_option): (AdditionalConfigDiscriminants, _) =
        from_wrapped_enum(cx, wrapped.upcast())?;

    if obj_option.is_none() {
        return Err(ConversionError::MissingEnumValues);
    }

    let obj = js_result(obj_option.unwrap().downcast::<JsObject, _>(cx))?;

    let result = match additional_config {
        AdditionalConfigDiscriminants::FileStoreConfig => {
            let db_path_js = missing_enum_values(obj.get::<JsString, _, _>(cx, "db_path"))?;
            let secure_path_js = missing_enum_values(obj.get::<JsString, _, _>(cx, "secure_path"))?;
            let pass_js = missing_enum_values(obj.get::<JsString, _, _>(cx, "pass"))?;

            AdditionalConfig::FileStoreConfig {
                db_path: db_path_js.value(cx),
                secure_path: secure_path_js.value(cx),
                pass: pass_js.value(cx),
            }
        }
        AdditionalConfigDiscriminants::KVStoreConfig => {
            let get_fn_js = missing_enum_values(obj.get::<JsFunction, _, _>(cx, "get_fn"))?;
            let store_fn_js = missing_enum_values(obj.get::<JsFunction, _, _>(cx, "store_fn"))?;
            let delete_fn_js = missing_enum_values(obj.get::<JsFunction, _, _>(cx, "delete_fn"))?;
            let all_keys_js = missing_enum_values(obj.get::<JsFunction, _, _>(cx, "all_keys_fn"))?;

            AdditionalConfig::KVStoreConfig {
                get_fn: (),
                store_fn: (),
                delete_fn: (),
                all_keys_fn: (),
            }
        }
        AdditionalConfigDiscriminants::StorageConfig => {
            let key_handle_js =
                missing_enum_values(obj.get::<KeyHandleJs, _, _>(cx, "key_handle"))?;

            let key_handle = key_handle_js.borrow();

            AdditionalConfig::StorageConfig {
                key_handle: key_handle.clone(),
            }
        }
    };

    Ok(result)
}

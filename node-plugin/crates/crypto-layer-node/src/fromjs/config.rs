
use crypto_layer::common::config::AdditionalConfigDiscriminants;
use crypto_layer::prelude::*;
use neon::prelude::*;

use super::error::{js_result, missing_enum_values, ConversionError};
use super::{
    from_wrapped_enum, from_wrapped_simple_enum, wrapped_array_to_hash_set,
};
use crate::{JsKeyHandle, JsKeyPairHandle};

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
    let additional_config_js_arr: Handle<'_, JsArray> =
        js_result(wrapped.get(cx, "additional_config"))?;
    let additional_config_arr = js_result(additional_config_js_arr.to_vec(cx))?;

    let mut res = vec![];
    for additional_config in additional_config_arr {
        let additional_config_obj = js_result(additional_config.downcast::<JsObject, _>(cx))?;
        res.push(js_result(from_wrapped_additional_config(
            cx,
            additional_config_obj,
        ))?);
    }

    Ok(ProviderImplConfig {
        additional_config: res,
    })
}

pub fn from_wrapped_additional_config(
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
            let db_path_js = missing_enum_values(obj.get::<JsString, _, _>(cx, "db_dir"))?;

            AdditionalConfig::FileStoreConfig {
                db_dir: db_path_js.value(cx),
            }
        }
        AdditionalConfigDiscriminants::KVStoreConfig => {
            // Implementing this is problamatic:
            // There is only one node thread running.
            // Meaning that to call methods given to rust, rust queues theses method calls for node to run, when the thread
            // is available.
            // Rust waits for the call to finish. It never does, as the call can only execute, when the thread is free.
            unimplemented!()
        }
        AdditionalConfigDiscriminants::StorageConfigHMAC => {
            let key: &'static str = AdditionalConfigDiscriminants::StorageConfigHMAC.into();
            let key_handle_js = missing_enum_values(wrapped.get::<JsKeyHandle, _, _>(cx, key))?;

            let key_handle = key_handle_js.borrow();

            AdditionalConfig::StorageConfigHMAC (
                key_handle.clone()
            )
        }
        AdditionalConfigDiscriminants::StorageConfigDSA => {
            let key: &'static str = AdditionalConfigDiscriminants::StorageConfigDSA.into();
            let key_pair_handle_js = missing_enum_values(wrapped.get::<JsKeyPairHandle, _, _>(cx, key))?;

            let key_pair_handle = key_pair_handle_js.borrow();

            AdditionalConfig::StorageConfigDSA (
                key_pair_handle.clone()
            )
        }
        AdditionalConfigDiscriminants::StorageConfigPass => {
            let key: &'static str = AdditionalConfigDiscriminants::StorageConfigHMAC.into();
            let pass_js = missing_enum_values(wrapped.get::<JsString, _, _>(cx, key))?;
            AdditionalConfig::StorageConfigPass(pass_js.value(cx))
        }
    };

    Ok(result)
}

pub(crate) fn from_wrapped_key_spec(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<KeySpec, ConversionError> {
    let cipher_js = js_result(wrapped.get(cx, "cipher"))?;
    let signing_hash_js = js_result(wrapped.get(cx, "signing_hash"))?;
    let ephemeral_js = js_result(wrapped.get::<JsBoolean, _, _>(cx, "ephemeral"))?;

    Ok(KeySpec {
        cipher: from_wrapped_simple_enum(cx, cipher_js)?,
        signing_hash: from_wrapped_simple_enum(cx, signing_hash_js)?,
        ephemeral: ephemeral_js.value(cx),
    })
}

pub(crate) fn from_wrapped_key_pair_spec(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<KeyPairSpec, ConversionError> {
    let asymc_spec_js = js_result(wrapped.get(cx, "asym_spec"))?;
    let cipher_js = js_result(wrapped.get::<JsValue, _, _>(cx, "cipher"))?;
    let signing_hash_js = js_result(wrapped.get(cx, "signing_hash"))?;
    let ephemeral_js = js_result(wrapped.get::<JsBoolean, _, _>(cx, "ephemeral"))?;

    let cipher = if let Ok(cipher_js_str) = cipher_js.downcast::<JsString, _>(cx) {
        Some(from_wrapped_simple_enum(cx, cipher_js_str.upcast())?)
    } else {
        None
    };

    Ok(KeyPairSpec {
        asym_spec: from_wrapped_simple_enum(cx, asymc_spec_js)?,
        cipher: cipher,
        signing_hash: from_wrapped_simple_enum(cx, signing_hash_js)?,
        ephemeral: ephemeral_js.value(cx),
    })
}

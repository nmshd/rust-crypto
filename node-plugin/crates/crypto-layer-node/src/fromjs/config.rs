use crypto_layer::common::config::AdditionalConfigDiscriminants;
use crypto_layer::prelude::*;
use neon::prelude::*;

use super::error::{bad_parameter, js_result, rw_lock_poisoned, ConversionError};
use super::{from_wrapped_enum, from_wrapped_simple_enum, wrapped_array_to_hash_set};
use crate::{JsKeyHandle, JsKeyPairHandle};

/// Converts `ProviderConfig` from `crypto-layer-ts-types` to `ProviderConfig` from `crypto-layer`.
#[tracing::instrument(level = "trace", skip_all)]
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
    let supported_asym_spec_arr =
        js_result(wrapped.get::<JsArray, _, _>(cx, "supported_asym_spec"))?;

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

/// Converts `ProviderImplConfig` from `crypto-layer-ts-types` to `ProviderImplConfig` from `crypto-layer`.
#[tracing::instrument(level = "trace", skip_all)]
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
        res.push(from_wrapped_additional_config(cx, additional_config_obj)?);
    }

    Ok(ProviderImplConfig {
        additional_config: res,
    })
}

/// Converts `AdditionalConfig` from `crypto-layer-ts-types` to `AdditionalConfig` from `crypto-layer`.
///
/// # Errors
/// * `KVStoreConfig` is currently not supported and will crash the program with `unimplemented!()`.
#[tracing::instrument(level = "trace", skip_all)]
pub fn from_wrapped_additional_config(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<AdditionalConfig, ConversionError> {
    let (additional_config, obj_option): (AdditionalConfigDiscriminants, _) =
        from_wrapped_enum(cx, wrapped.upcast())?;

    if obj_option.is_none() {
        tracing::error!("Value is not of type object or string.");
        return Err(ConversionError::BadParameter);
    }

    let obj = obj_option.unwrap();

    let result = match additional_config {
        AdditionalConfigDiscriminants::FileStoreConfig => {
            let obj = bad_parameter(obj.downcast::<JsObject, _>(cx))?;
            let db_path_js = bad_parameter(obj.get::<JsString, _, _>(cx, "db_dir"))?;

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
            let key_handle_js = bad_parameter(obj.downcast::<JsKeyHandle, _>(cx))?;

            let key_handle = rw_lock_poisoned(key_handle_js.read())?;

            AdditionalConfig::StorageConfigHMAC(key_handle.clone())
        }
        AdditionalConfigDiscriminants::StorageConfigDSA => {
            let key_pair_handle_js = bad_parameter(obj.downcast::<JsKeyPairHandle, _>(cx))?;

            let key_pair_handle = rw_lock_poisoned(key_pair_handle_js.read())?;

            AdditionalConfig::StorageConfigDSA(key_pair_handle.clone())
        }
        AdditionalConfigDiscriminants::StorageConfigPass => {
            let pass_js = bad_parameter(obj.downcast::<JsString, _>(cx))?;
            AdditionalConfig::StorageConfigPass(pass_js.value(cx))
        }
    };

    Ok(result)
}

/// Converts `KeySpec` from `crypto-layer-ts-types` to `KeySpec` from `crypto-layer`.
#[tracing::instrument(level = "trace", skip_all)]
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

/// Converts `KeyPairSpec` from `crypto-layer-ts-types` to `KeyPairSpec` from `crypto-layer`.
#[tracing::instrument(level = "trace", skip_all)]
pub(crate) fn from_wrapped_key_pair_spec(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<KeyPairSpec, ConversionError> {
    let asymc_spec_js = js_result(wrapped.get(cx, "asym_spec"))?;
    let cipher_js = js_result(wrapped.get::<JsValue, _, _>(cx, "cipher"))?;
    let signing_hash_js = js_result(wrapped.get(cx, "signing_hash"))?;
    let ephemeral_js = js_result(wrapped.get::<JsBoolean, _, _>(cx, "ephemeral"))?;
    let non_exportable_js = js_result(wrapped.get::<JsBoolean, _, _>(cx, "non_exportable"))?;

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
        non_exportable: non_exportable_js.value(cx),
    })
}

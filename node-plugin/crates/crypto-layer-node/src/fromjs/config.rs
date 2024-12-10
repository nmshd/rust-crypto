use std::boxed::Box;
use std::future::ready;
use std::sync::Arc;

use crypto_layer::common::config::AdditionalConfigDiscriminants;
use crypto_layer::common::config::{AllKeysFn, DeleteFn, GetFn, StoreFn};
use crypto_layer::prelude::*;
use neon::prelude::*;
use neon::types::buffer::TypedArray;
use tracing::{error, trace, trace_span};

use super::error::{js_result, missing_enum_values, ConversionError};
use super::{
    from_wrapped_enum, from_wrapped_simple_enum, from_wrapped_string_vec, wrapped_array_to_hash_set,
};
use crate::JsKeyHandle;

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
            let get_fn_js =
                missing_enum_values(obj.get::<JsFunction, _, _>(cx, "get_fn"))?.root(cx);
            let get_fn: GetFn = {
                let channel = cx.channel();
                let get_fn = Arc::new(get_fn_js);

                Arc::new(move |id| {
                    let _span = trace_span!("GetFn Closure", id);

                    let get_fn = get_fn.clone();
                    let cloned_id = id.clone();

                    let handle = channel.send(move |mut cx| {
                        let _inner_span = trace_span!("GetFn Node Executed", id);
                        let res = match get_fn
                            .to_inner(&mut cx)
                            .call_with(&cx)
                            .arg(cx.string(&id))
                            .apply::<JsValue, _>(&mut cx)
                        {
                            Ok(res) => match res.downcast::<JsUint8Array, _>(&mut cx) {
                                Ok(arr) => Some(arr.buffer(&mut cx).as_mut_slice(&mut cx).into()),
                                Err(e) => {
                                    error!(error = %e, id, "Failed converting fetched data to rust vec.");
                                    None
                                }
                            },
                            Err(e) => {
                                error!(error = %e, id, "Failed Fetching with GetFn.");
                                None
                            }
                        };
                        Ok(res)
                    });

                    let _join_span = trace_span!("Joining node executed GetFn.");
                    let res: Option<Vec<u8>> = match js_result(handle.join()) {
                        Ok(res) => res,
                        Err(e) => {
                            error!(error = %e, id = cloned_id, "Unsuccessfull join of GetFn.");
                            None
                        }
                    };

                    Box::pin(ready(res))
                })
            };

            let store_fn_js =
                missing_enum_values(obj.get::<JsFunction, _, _>(cx, "store_fn"))?.root(cx);
            let store_fn: StoreFn = {
                let channel = cx.channel();
                let store_fn = Arc::new(store_fn_js);

                Arc::new(move |id, data| {
                    let _span = trace_span!("StoreFn Closure", id);

                    let store_fn = store_fn.clone();
                    let cloned_id = id.clone();

                    let handle = channel.send(move |mut cx| {
                        let _inner_span = trace_span!("GetFn Node Executed", id);
                        let res = match store_fn
                            .to_inner(&mut cx)
                            .call_with(&cx)
                            .arg(cx.string(&id))
                            .arg(JsUint8Array::from_slice(&mut cx, &data)?)
                            .apply::<JsBoolean, _>(&mut cx)
                        {
                            Ok(res) => res.value(&mut cx),
                            Err(e) => {error!(id, error = %e, "Unsuccessfull execution of StoreFn through nodejs."); false},
                        };
                        Ok(res)
                    });

                    let _join_span = trace_span!("Joining node executed GetFn.");
                    let res = match js_result(handle.join()) {
                        Ok(res) => res,
                        Err(e) => {
                            error!(id = cloned_id, error = %e, "Unsuccessfull join of StoreFn.");
                            false
                        }
                    };

                    Box::pin(ready(res))
                })
            };

            let delete_fn_js =
                missing_enum_values(obj.get::<JsFunction, _, _>(cx, "delete_fn"))?.root(cx);
            let delete_fn: DeleteFn = {
                let channel = cx.channel();
                let delete_fn = Arc::new(delete_fn_js);

                Arc::new(move |id| {
                    let _span = trace_span!("DeleteKeyFn Closure", id);
                    let delete_fn = delete_fn.clone();
                    let cloned_id = id.clone();

                    let handle = channel.send(move |mut cx| {
                        let _inner_span = trace_span!("DeleteFn Node Executed", id);
                        delete_fn
                            .to_inner(&mut cx)
                            .call_with(&cx)
                            .arg(cx.string(&id))
                            .apply::<JsUndefined, _>(&mut cx)?;
                        Ok(())
                    });

                    if let Err(e) = handle.join() {
                        error!(id = cloned_id, error = %e, "DeleteKeyFn Failure");
                    }

                    Box::pin(ready(()))
                })
            };

            let all_keys_js =
                missing_enum_values(obj.get::<JsFunction, _, _>(cx, "all_keys_fn"))?.root(cx);
            let all_keys_fn: AllKeysFn = {
                let _span = trace_span!("AllKeysFn Closure");
                let channel = cx.channel();
                let all_keys_fn = Arc::new(all_keys_js);

                Arc::new(move || {
                    let _inner_span = trace_span!("AllKeysFn Closure");
                    let all_keys_fn = all_keys_fn.clone();

                    let handle = channel.send(move |mut cx| {
                        let res = match all_keys_fn
                            .to_inner(&mut cx)
                            .call_with(&cx)
                            .apply::<JsArray, _>(&mut cx)
                        {
                            Ok(res) => match from_wrapped_string_vec(&mut cx, res) {
                                Ok(string_vec) => string_vec,
                                Err(e) => {
                                    error!(error = %e, "Failed conversion of js type to rs type.");
                                    vec![]
                                }
                            },
                            Err(e) => {
                                error!(error = %e, "Failed execution of GetAllKeysFn nodejs.");
                                vec![]
                            }
                        };
                        Ok(res)
                    });

                    let res = match handle.join() {
                        Ok(res) => res,
                        Err(e) => {
                            error!(error = %e, "Unsuccessfull join of GetAllKeysFn.");
                            vec![]
                        }
                    };

                    Box::pin(ready(res))
                })
            };

            AdditionalConfig::KVStoreConfig {
                get_fn,
                store_fn,
                delete_fn,
                all_keys_fn,
            }
        }
        AdditionalConfigDiscriminants::StorageConfig => {
            let key_handle_js =
                missing_enum_values(obj.get::<JsKeyHandle, _, _>(cx, "key_handle"))?;

            let key_handle = key_handle_js.borrow();

            AdditionalConfig::StorageConfig {
                key_handle: key_handle.clone(),
            }
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

    Ok(KeySpec {
        cipher: from_wrapped_simple_enum(cx, cipher_js)?,
        signing_hash: from_wrapped_simple_enum(cx, signing_hash_js)?,
    })
}

pub(crate) fn from_wrapped_key_pair_spec(
    cx: &mut FunctionContext,
    wrapped: Handle<JsObject>,
) -> Result<KeyPairSpec, ConversionError> {
    let asymc_spec_js = js_result(wrapped.get(cx, "asym_spec"))?;
    let cipher_js = js_result(wrapped.get::<JsValue, _, _>(cx, "cipher"))?;
    let signing_hash_js = js_result(wrapped.get(cx, "signing_hash"))?;

    let cipher = if let Ok(cipher_js_str) = cipher_js.downcast::<JsString, _>(cx) {
        Some(from_wrapped_simple_enum(cx, cipher_js_str.upcast())?)
    } else {
        None
    };

    Ok(KeyPairSpec {
        asym_spec: from_wrapped_simple_enum(cx, asymc_spec_js)?,
        cipher: cipher,
        signing_hash: from_wrapped_simple_enum(cx, signing_hash_js)?,
    })
}

use crypto_layer::common::config::ProviderImplConfig;

use flutter_rust_bridge::DartFnFuture;
use std::sync::Mutex;

#[cfg(target_os = "android")]
use std::any::Any;
#[cfg(target_os = "android")]
use std::sync::Arc;

pub async fn get_default_config(
    get_fn: impl Fn(String) -> DartFnFuture<Option<Vec<u8>>> + 'static + Send + Sync,
    store_fn: impl Fn(String, Vec<u8>) -> DartFnFuture<bool> + 'static + Send + Sync,
    delete_fn: impl Fn(String) -> DartFnFuture<()> + 'static + Send + Sync,
    all_keys_fn: impl Fn() -> DartFnFuture<Vec<String>> + 'static + Send + Sync,
) -> ProviderImplConfig {
    #[cfg(target_os = "android")]
    let java_vm = Some(
        Arc::new(Mutex::new(crate::api::android::get_java_vm())) as Arc<dyn Any + Send + Sync>
    );
    #[cfg(not(target_os = "android"))]
    let java_vm = None;

    ProviderImplConfig::new(java_vm, get_fn, store_fn, delete_fn, all_keys_fn)
}

use crypto_layer::common::config::ProviderImplConfig;

use flutter_rust_bridge::DartFnFuture;

pub async fn get_default_config(
    get_fn: impl Fn(String) -> DartFnFuture<Option<Vec<u8>>> + 'static + Send + Sync,
    store_fn: impl Fn(String, Vec<u8>) -> DartFnFuture<bool> + 'static + Send + Sync,
    delete_fn: impl Fn(String) -> DartFnFuture<()> + 'static + Send + Sync,
    all_keys_fn: impl Fn() -> DartFnFuture<Vec<String>> + 'static + Send + Sync,
) -> ProviderImplConfig {

    ProviderImplConfig::new(get_fn, store_fn, delete_fn, all_keys_fn)
}

#[cfg(feature = "flutter")]
use flutter_rust_bridge::{frb, RustAutoOpaqueNom};
use once_cell::sync::Lazy;
use std::collections::HashMap;

use super::{
    config::{self, ProviderConfig, ProviderImplConfig},
    traits::module_provider::ProviderFactory,
    Provider,
};
use crate::stub::StubProviderFactory;
#[cfg(feature = "android")]
use crate::tpm::android::provider::AndroidProviderFactory;

static ALL_PROVIDERS: Lazy<Vec<Box<dyn ProviderFactory>>> = Lazy::new(|| {
    vec![
        #[cfg(feature = "android")]
        Box::new(AndroidProviderFactory {}),
        Box::new(StubProviderFactory {}),
    ]
});

#[cfg_attr(feature = "flutter", frb(non_opaque))]
fn provider_supports_capabilities(
    provider_capabilities: &ProviderConfig,
    needed_capabilities: &ProviderConfig,
) -> bool {
    provider_capabilities.max_security_level <= needed_capabilities.max_security_level
        && provider_capabilities.min_security_level >= needed_capabilities.min_security_level
        && needed_capabilities
            .supported_asym_spec
            .is_subset(&provider_capabilities.supported_asym_spec)
        && needed_capabilities
            .supported_ciphers
            .is_subset(&provider_capabilities.supported_ciphers)
        && needed_capabilities
            .supported_hashes
            .is_subset(&provider_capabilities.supported_hashes)
}

/// Returns a provider which supports the given requierements.
///
/// This function returns the first provider, which supports the given requirements and has a [ProviderImplConfig].
///
/// * `conf` - A provider config that the provider must at least contain.
/// * `impl_conf_vec` - A `Vec` of [ProviderImplConfig]. Only providers, which have [ProviderImplConfig] are returned.
///
/// # Example
/// ```
/// use std::collections::HashSet;
///
/// use async_std::task::block_on;
///
/// use crypto_layer::common::{
///     config::*,
///     factory::*,
/// };
///
/// fn main() {
///     let specific_provider_config = vec![ProviderImplConfig::Stub {}];
///     let provider_config = ProviderConfig {
///        min_security_level: SecurityLevel::Software,
///        max_security_level: SecurityLevel::Hardware,
///        supported_asym_spec: HashSet::new(),
///        supported_ciphers: HashSet::new(),
///        supported_hashes: HashSet::new(),
///     };
///     let provider = block_on(create_provider(provider_config, specific_provider_config)).unwrap();
/// }
/// ```
// #[cfg_attr(feature = "flutter", frb)]
pub async fn create_provider(
    conf: ProviderConfig,
    impl_conf_vec: Vec<ProviderImplConfig>,
) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        let name = provider.get_name();
        let config = match impl_conf_vec.iter().find(|e| e.name() == name) {
            Some(config) => config.clone(),
            None => continue,
        };
        let provider_caps = provider.get_capabilities(config.clone()).await;
        if provider_supports_capabilities(&provider_caps, &conf) {
            #[cfg(feature = "flutter")]
            return Some(Provider {
                implementation: RustAutoOpaqueNom::new(provider.create_provider(config).await),
            });
            #[cfg(not(feature = "flutter"))]
            return Some(Provider {
                implementation: provider.create_provider(config).await,
            });
        }
    }
    None
}

/// Returns the provider with the given name.
///
/// * `name` - Name of the provider. See `get_name()`.
/// * `impl_config` - Specif configuration for said provider.
// #[cfg_attr(feature = "flutter", frb(non_opaque))]
pub async fn create_provider_from_name(
    name: String,
    impl_conf: ProviderImplConfig,
) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        if provider.get_name() == name {
            #[cfg(feature = "flutter")]
            return Some(Provider {
                implementation: RustAutoOpaqueNom::new(provider.create_provider(impl_conf).await),
            });
            #[cfg(not(feature = "flutter"))]
            return Some(Provider {
                implementation: provider.create_provider(impl_conf).await,
            });
        }
    }
    None
}

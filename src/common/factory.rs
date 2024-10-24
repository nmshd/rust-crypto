use std::collections::HashMap;

use flutter_rust_bridge::{frb, RustAutoOpaqueNom};
use once_cell::sync::Lazy;

use super::{
    config::{self, ProviderConfig, ProviderImplConfig},
    traits::module_provider::{ProviderFactory, ProviderFactoryEnum},
    Provider,
};
use crate::stub::StubProviderFactory;
#[cfg(feature = "android")]
use crate::tpm::android::provider::AndroidProviderFactory;

static ALL_PROVIDERS: Lazy<Vec<ProviderFactoryEnum>> = Lazy::new(|| {
    vec![
        #[cfg(feature = "android")]
        Into::into(AndroidProviderFactory {}),
        Into::into(StubProviderFactory {}),
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
pub fn create_provider(
    conf: ProviderConfig,
    impl_conf_vec: Vec<ProviderImplConfig>,
) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        let name = provider.get_name();

        let config = match impl_conf_vec.iter().find(|e| e.name() == name) {
            Some(config) => config.clone(),
            None => continue,
        };
        let provider_caps = provider.get_capabilities(config.clone());

        if provider_supports_capabilities(&provider_caps, &conf) {
            return Some(Provider {
                implementation: provider.create_provider(config),
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
pub fn create_provider_from_name(name: String, impl_conf: ProviderImplConfig) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        let p_name = provider.get_name();

        if p_name == name {
            return Some(Provider {
                implementation: provider.create_provider(impl_conf),
            });
        }
    }
    None
}

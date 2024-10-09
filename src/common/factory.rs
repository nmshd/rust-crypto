use std::collections::HashMap;

use once_cell::sync::Lazy;

use super::{
    config::{self, ProviderConfig, ProviderImplConfig},
    traits::module_provider::ProviderFactory,
    Provider,
};
use crate::stub::StubProviderFactory;

static ALL_PROVIDERS: Lazy<Vec<Box<dyn ProviderFactory>>> =
    Lazy::new(|| vec![Box::new(StubProviderFactory {})]);

fn provider_supports_capabilities(
    provider_capabilities: &ProviderConfig,
    needed_capabilities: &ProviderConfig,
) -> bool {
    provider_capabilities.max_security_level >= needed_capabilities.max_security_level
        && provider_capabilities.min_security_level <= needed_capabilities.min_security_level
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
/// use crypto_layer::common::{
///     config::*,
///     factory::*,
/// };
///
/// fn main() {
///     let specific_provider_config = vec![ProviderImplConfig::Stub {}, ProviderImplConfig::Android {}];
///     let provider_config = ProviderConfig {
///        min_security_level: SecurityLevel::Software,
///        max_security_level: SecurityLevel::Hardware,
///        supported_asym_spec: HashSet::new(),
///        supported_ciphers: HashSet::new(),
///        supported_hashes: HashSet::new(),
///     };
///     let provider = create_provider(provider_config, specific_provider_config).unwrap();
/// }
/// ```
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
        let provider_caps = provider.get_capabilities(config).await;
        if provider_supports_capabilities(&provider_caps, &conf) {
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
pub async fn create_provider_from_name(
    name: String,
    impl_conf: ProviderImplConfig,
) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        if provider.get_name() == name {
            return Some(Provider {
                implementation: provider.create_provider(impl_conf).await,
            });
        }
    }
    None
}

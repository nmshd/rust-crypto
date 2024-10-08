use std::collections::HashMap;

use super::{
    config::{ProviderConfig, ProviderImplConfig},
    traits::module_provider::ProviderFactory,
    Provider,
};
use crate::stub::StubProviderFactory;

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
/// This function returns a provider if any provider supports the given requirements and
/// the hash map contains as key said providers name.
///
/// * `conf` - A provider config that the provider must at least contain.
/// * `impl_conf_map` - A [HashMap] where the keys must be provider names and the values must be said providers specific configuration.
pub async fn create_provider(
    conf: ProviderConfig,
    impl_conf_map: HashMap<String, ProviderImplConfig>,
) -> Option<Provider> {
    let all_providers = vec![Box::new(StubProviderFactory {})];
    for mut provider in all_providers {
        let provider_name = provider.get_name();
        let impl_conf = match impl_conf_map.get(&provider_name) {
            Some(impl_conf) => *impl_conf,
            None => continue,
        };
        let provider_caps = provider.get_capabilities(impl_conf).await;
        if provider_supports_capabilities(&provider_caps, &conf) {
            return Some(Provider {
                implementation: provider.create_provider(impl_conf).await,
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
    let all_providers = vec![Box::new(StubProviderFactory {})];
    for provider in all_providers {
        // ALL_PROVIDERS is a compile time list of enabled providers
        if provider.get_name() == name {
            return Some(Provider {
                implementation: provider.create_provider(impl_conf).await,
            });
        }
    }
    None
}

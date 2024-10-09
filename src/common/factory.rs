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

pub async fn create_provider(conf: ProviderConfig, impl_conf: ProviderImplConfig) -> Provider {
    let all_providers = vec![Box::new(StubProviderFactory {})];
    for mut provider in all_providers {
        let provider_caps = provider.get_capabilities(impl_conf.clone()).await;
        if provider_supports_capabilities(&provider_caps, &conf) {
            return Provider {
                implementation: provider.create_provider(impl_conf).await,
            };
        }
    }
    panic!();
}

pub async fn create_provider_from_name(name: String, impl_conf: ProviderImplConfig) -> Provider {
    let all_providers = vec![Box::new(StubProviderFactory {})];
    for provider in all_providers {
        // ALL_PROVIDERS is a compile time list of enabled providers
        if provider.get_name() == name {
            return Provider {
                implementation: provider.create_provider(impl_conf).await,
            };
        }
    }
    panic!()
}

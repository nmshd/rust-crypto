use std::sync::LazyLock;

use super::{
    config::{ProviderConfig, ProviderImplConfig},
    traits::module_provider::{ProviderFactory, ProviderFactoryEnum},
    Provider,
};
#[cfg(feature = "software")]
use crate::software::SoftwareProviderFactory;
use crate::stub::StubProviderFactory;
#[cfg(feature = "android")]
use crate::tpm::android::provider::AndroidProviderFactory;
#[cfg(feature = "apple-secure-enclave")]
use crate::tpm::apple_secure_enclave::provider::AppleSecureEnclaveFactory;

static ALL_PROVIDERS: LazyLock<Vec<ProviderFactoryEnum>> = LazyLock::new(|| {
    vec![
        #[cfg(feature = "android")]
        Into::into(AndroidProviderFactory {
            secure_element: true,
        }),
        #[cfg(feature = "android")]
        Into::into(AndroidProviderFactory {
            secure_element: false,
        }),
        Into::into(StubProviderFactory {}),
        #[cfg(feature = "apple-secure-enclave")]
        Into::into(AppleSecureEnclaveFactory {}),
        #[cfg(feature = "software")]
        Into::into(SoftwareProviderFactory {}),
    ]
});

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
/// use crypto_layer::common::{
///     config::*,
///     factory::*,
/// };
///
/// let specific_provider_config = ProviderImplConfig{additional_config: vec![]};
/// let provider_config = ProviderConfig {
///     min_security_level: SecurityLevel::Software,
///     max_security_level: SecurityLevel::Hardware,
///     supported_asym_spec: HashSet::new(),
///     supported_ciphers: HashSet::new(),
///     supported_hashes: HashSet::new(),
/// };
/// let provider = create_provider(provider_config, specific_provider_config).unwrap();
/// ```
pub fn create_provider(conf: ProviderConfig, impl_conf: ProviderImplConfig) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        let provider_caps = provider.get_capabilities(impl_conf.clone());
        let supported = provider_caps.map(|caps| provider_supports_capabilities(&caps, &conf));
        if supported.unwrap_or(false) {
            return Some(Provider {
                implementation: provider.create_provider(impl_conf),
            });
        }
    }
    None
}

/// Returns the provider with the given name.
///
/// * `name` - Name of the provider. See `get_name()`.
/// * `impl_config` - Specif configuration for said provider.
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

/// Returns the names of all available providers for testing.
pub fn get_all_providers() -> Vec<String> {
    ALL_PROVIDERS.iter().map(|p| p.get_name()).collect()
}

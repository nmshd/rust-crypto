//!
//! There are essentially two ways of getting your first provider:
//! 1. Create a [`ProviderConfig`] that represents your needs
//!     and then use [`create_provider`] to get assigned a provider automatically.
//! 2. Use [`get_all_providers`] and [`get_provider_capabilities`]
//!     to find a suitable provider and use [`create_provider_from_name`] to create said provider.
//!
//! As keys are bound to their respective provider, it is advisable
//! to store the used providers and recreate them with [`create_provider_from_name`].
//!
//! [`create_provider`]: crate::common::factory::create_provider
//! [`get_all_providers`]: crate::common::factory::get_all_providers
//! [`get_provider_capabilities`]: crate::common::factory::get_provider_capabilities
//! [`create_provider_from_name`]: crate::common::factory::create_provider_from_name

use std::sync::LazyLock;

use tracing::{trace, warn};

use super::{
    config::{ProviderConfig, ProviderImplConfig},
    traits::module_provider::{ProviderFactory, ProviderFactoryEnum},
    Provider,
};
#[cfg(feature = "android")]
use crate::provider::android::provider::AndroidProviderFactory;
#[cfg(feature = "apple-secure-enclave")]
use crate::provider::apple_secure_enclave::provider::AppleSecureEnclaveFactory;
#[cfg(feature = "software")]
use crate::provider::software::SoftwareProviderFactory;

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

/// Returns a provider which supports the given requirements.
///
/// This function returns the first provider, which supports the given requirements and has a [`ProviderImplConfig`].
///
/// * `conf` - A provider config that the provider must at least contain.
/// * `impl_conf_vec` - A `Vec` of [`ProviderImplConfig`]. Only providers, which have [`ProviderImplConfig`] are returned.
///
/// # Example
/// ```
/// use std::collections::HashSet;
///
/// use crypto_layer::prelude::*;
///
/// let specific_provider_config = ProviderImplConfig{additional_config: vec![]};
/// let provider_config = ProviderConfig {
///     min_security_level: SecurityLevel::Software,
///     max_security_level: SecurityLevel::Hardware,
///     supported_asym_spec: HashSet::new(),
///     supported_ciphers: HashSet::new(),
///     supported_hashes: HashSet::new(),
/// };
///
/// let provider_option: Option<Provider> = create_provider(&provider_config, specific_provider_config);
/// ```
pub fn create_provider(conf: &ProviderConfig, impl_conf: ProviderImplConfig) -> Option<Provider> {
    for provider in ALL_PROVIDERS.iter() {
        let provider_caps = provider.get_capabilities(impl_conf.clone());
        let supported = provider_caps.map(|caps| provider_supports_capabilities(&caps, conf));
        if supported.unwrap_or(false) {
            return Some(Provider {
                implementation: match provider.create_provider(impl_conf) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Error creating provider: {:?}", e);
                        return None;
                    }
                },
            });
        }
    }
    None
}

/// Returns the provider matching the given name.
///
/// * `name` - Name of the provider. See `get_name()`.
/// * `impl_config` - Specif configuration for said provider.
#[tracing::instrument]
pub fn create_provider_from_name(name: &str, impl_conf: ProviderImplConfig) -> Option<Provider> {
    trace!("create_provider_from_name: {}", name);
    for provider in ALL_PROVIDERS.iter() {
        let p_name = provider.get_name();

        if p_name.as_deref() == Some(name) {
            return Some(Provider {
                implementation: match provider.create_provider(impl_conf) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Error creating provider: {:?}", e);
                        return None;
                    }
                },
            });
        }
    }
    warn!("Error creating provider: No Provider with name {:?}", name);
    None
}

/// Returns the names of all available providers.
pub fn get_all_providers() -> Vec<String> {
    ALL_PROVIDERS
        .iter()
        .filter_map(ProviderFactory::get_name)
        .collect()
}

/// Returns the names and capabilities of all providers that can be initialized with the given [ProviderImplConfig].
pub fn get_provider_capabilities(impl_config: ProviderImplConfig) -> Vec<(String, ProviderConfig)> {
    ALL_PROVIDERS
        .iter()
        .filter_map(|fac| {
            fac.get_capabilities(impl_config.clone())
                .map(|caps| (fac.get_name().expect("When get_capabilities returned Some, get_name must return Some too. This is an internal error"), caps))
        })
        .collect()
}

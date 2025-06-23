use std::collections::HashSet;

use crate::{
    common::traits::module_provider::{ProviderFactory, ProviderImplEnum},
    prelude::{CalError, ProviderConfig, ProviderImplConfig, SecurityLevel},
    provider::linux::provider::LinuxProvider,
    storage::StorageManager,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct LinuxProviderFactory;

impl ProviderFactory for LinuxProviderFactory {
    fn get_name(&self) -> Option<String> {
        // TODO: check if TPM is accessible
        Some(super::NAME.to_owned())
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        Some(ProviderConfig {
            min_security_level: SecurityLevel::Hardware,
            max_security_level: SecurityLevel::Hardware,
            supported_asym_spec: HashSet::new(),
            supported_ciphers: HashSet::new(),
            supported_hashes: HashSet::new(),
        })
    }

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        let storage_manager =
            StorageManager::new(self.get_name().unwrap(), &impl_config.additional_config)?;

        Ok(ProviderImplEnum::from(LinuxProvider {
            impl_config,
            used_factory: *self,
            storage_manager,
        }))
    }
}

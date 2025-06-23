use crate::{
    common::traits::module_provider::ProviderFactory,
    prelude::{AdditionalConfig, ProviderImplConfig},
    provider::linux::provider_factory::LinuxProviderFactory,
    tests::setup,
};

#[test]
fn test_create_provider() {
    setup();
    let provider = LinuxProviderFactory {}.create_provider(ProviderImplConfig {
        additional_config: vec![AdditionalConfig::StorageConfigPass("test".to_string())],
    });

    provider.expect("provider should be created");
}

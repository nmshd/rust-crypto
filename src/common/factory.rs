use std::{cell::Cell, rc::Rc};

use super::{
    config::ProviderConfig,
    traits::module_provider::{Provider, ProviderFactory},
};
use crate::stub::StubProviderFactory;

pub async fn create_provider(config: ProviderConfig) -> Box<dyn Provider> {
    let all_providers = vec![Box::new(StubProviderFactory {})];
    let config = Rc::new(config);
    Cell::new(config.clone());
    for mut provider in all_providers {
        // ALL_PROVIDERS is a compile time list of enabled providers
        if provider.check_config(*config.clone()).await {
            return provider.create_provider(*config).await;
        }
    }
    unreachable!()
}

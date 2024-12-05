use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;

use crate::fromjs;

pub(crate) struct WrappedProvider {
    provider: Provider,
}

impl WrappedProvider {
    pub(crate) fn new(provider: Provider) -> Self {
        Self { provider }
    }
}

impl Deref for WrappedProvider {
    type Target = Provider;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}

impl DerefMut for WrappedProvider {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.provider
    }
}

impl Finalize for WrappedProvider {}

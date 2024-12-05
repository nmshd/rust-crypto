use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;

use crate::fromjs;

pub(crate) struct WrappedDHExchange {
    dhexchange: DHExchange,
}

impl WrappedDHExchange {
    pub(crate) fn new(dhexchange: DHExchange) -> Self {
        Self { dhexchange }
    }
}

impl Deref for WrappedDHExchange {
    type Target = DHExchange;

    fn deref(&self) -> &Self::Target {
        &self.dhexchange
    }
}

impl DerefMut for WrappedDHExchange {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.dhexchange
    }
}

impl Finalize for WrappedDHExchange {}

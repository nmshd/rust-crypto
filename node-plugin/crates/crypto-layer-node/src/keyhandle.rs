use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;

use crate::fromjs;

pub(crate) struct WrappedKeyHandle {
    keyhandle: KeyHandle,
}

impl WrappedKeyHandle {
    pub(crate) fn new(keyhandle: KeyHandle) -> Self {
        Self { keyhandle }
    }
}

impl Deref for WrappedKeyHandle {
    type Target = KeyHandle;

    fn deref(&self) -> &Self::Target {
        &self.keyhandle
    }
}

impl DerefMut for WrappedKeyHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.keyhandle
    }
}

impl Finalize for WrappedKeyHandle {}

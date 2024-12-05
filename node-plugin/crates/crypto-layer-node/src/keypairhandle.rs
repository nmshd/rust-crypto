use std::ops::{Deref, DerefMut};

use crypto_layer::prelude::*;
use neon::prelude::*;

use crate::fromjs;

pub(crate) struct WrappedKeyPairHandle {
    key_pair_handle: KeyPairHandle,
}

impl WrappedKeyPairHandle {
    pub(crate) fn new(key_pair_handle: KeyPairHandle) -> Self {
        Self { key_pair_handle }
    }
}

impl Deref for WrappedKeyPairHandle {
    type Target = KeyPairHandle;

    fn deref(&self) -> &Self::Target {
        &self.key_pair_handle
    }
}

impl DerefMut for WrappedKeyPairHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key_pair_handle
    }
}

impl Finalize for WrappedKeyPairHandle {}

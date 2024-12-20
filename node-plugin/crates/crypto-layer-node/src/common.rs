use std::convert::From;
use std::ops::{Deref, DerefMut};

use neon::prelude::*;

/// Wrapper for empty [Finalize] trait implementation.
pub(crate) struct Finalized<T> {
    content: T,
}

impl<T> Finalized<T> {
    pub(crate) fn new(content: T) -> Self {
        Self { content }
    }
}

impl<T> Deref for Finalized<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.content
    }
}

impl<T> DerefMut for Finalized<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.content
    }
}

impl<T> Finalize for Finalized<T> {}

impl<T> From<T> for Finalized<T> {
    fn from(value: T) -> Self {
        Finalized::new(value)
    }
}

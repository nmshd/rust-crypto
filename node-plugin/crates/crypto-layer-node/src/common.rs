use std::convert::From;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, RwLock};

use blocking::unblock;
use crypto_layer::common::error::CalError;
use neon::prelude::*;

use crate::fromjs::error::unwrap_or_throw;

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

pub(crate) fn box_if_ok<'a, T>(
    cx: &mut impl Context<'a>,
    result_to_be_boxed: Result<T, CalError>,
) -> NeonResult<Handle<'a, JsBox<Arc<RwLock<Finalized<T>>>>>> {
    Ok(JsBox::new(
        cx,
        Arc::new(RwLock::new(Finalized::new(unwrap_or_throw!(
            cx,
            result_to_be_boxed
        )))),
    ))
}

macro_rules! arc_or_poisoned_error_deferred {
    ($channel:expr, $deferred:expr, $rwlock_access_expr:expr) => {{
        match $rwlock_access_expr {
            Ok(guard) => guard,
            Err(_) => {
                $deferred.settle_with($channel, |mut cx| {
                    tracing::error!("{}", crate::fromjs::error::ConversionError::RwLockPoisoned);
                    cx.throw_error::<_, Handle<JsValue>>(
                        crate::fromjs::error::ConversionError::RwLockPoisoned.to_string(),
                    )
                });
                return ();
            }
        }
    }};
}

pub(crate) use arc_or_poisoned_error_deferred;

pub(crate) fn spawn_promise<'a, F>(
    cx: &mut impl Context<'a>,
    func: F,
) -> NeonResult<Handle<'a, JsPromise>>
where
    F: Fn(Channel, neon::types::Deferred) -> () + Send + Sync + 'static,
{
    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    unblock(move || func(channel, deferred)).detach();

    Ok(promise)
}

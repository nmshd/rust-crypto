use traits::key_handle::DHKeyExchangeImplEnum;
use traits::key_handle::{KeyHandleImplEnum, KeyPairHandleImplEnum};
use traits::module_provider::ProviderImplEnum;

/// Structs and enumerations used for configuring providers, key and key pairs.
pub mod config;
/// Structs and enumerations representing cryptographic algorithms or standards.
pub mod crypto;
/// Struct for error handling.
pub mod error;
/// Functions used for creating providers.
pub mod factory;
pub mod traits;

// Do not delete this struct, it is a workaround for a bug in the code generation
/// ¯\_(ツ)_/¯
pub struct T {}

/// Abstraction of cryptographic providers.
///
/// [Provider] abstracts hardware, software and network based keystores.
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct Provider {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: ProviderImplEnum,
}

impl Deref for Provider {
    type Target = ProviderImplEnum;

    fn deref(&self) -> &Self::Target {
        &self.implementation
    }
}

impl DerefMut for Provider {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.implementation
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeyPairHandle {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: KeyPairHandleImplEnum,
}

impl Deref for KeyPairHandle {
    type Target = KeyPairHandleImplEnum;

    fn deref(&self) -> &Self::Target {
        &self.implementation
    }
}

impl DerefMut for KeyPairHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.implementation
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct KeyHandle {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: KeyHandleImplEnum,
}

impl Deref for KeyHandle {
    type Target = KeyHandleImplEnum;

    fn deref(&self) -> &Self::Target {
        &self.implementation
    }
}

impl DerefMut for KeyHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.implementation
    }
}

#[allow(dead_code)]
#[derive(Debug)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct DHExchange {
    #[cfg_attr(feature = "ts-interface", ts(skip))]
    pub(crate) implementation: DHKeyExchangeImplEnum,
}

impl Deref for DHExchange {
    type Target = DHKeyExchangeImplEnum;

    fn deref(&self) -> &Self::Target {
        &self.implementation
    }
}

impl DerefMut for DHExchange {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.implementation
    }
}

#[cfg(feature = "android")]
use crate::tpm::android::wrapper::context;
#[cfg(feature = "android")]
use std::ffi::c_void;
use std::ops::{Deref, DerefMut};
#[cfg(feature = "android")]
pub unsafe fn initialize_android_context(java_vm: *mut c_void, context_jobject: *mut c_void) {
    context::initialize_android_context(java_vm, context_jobject);
}

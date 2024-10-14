use async_trait::async_trait;

use crate::common::crypto::{
    algorithms::{
        encryption::{AsymmetricKeySpec, Cipher},
        hashes::CryptoHash,
    },
    KeyUsage,
};
use std::any::Any;

#[cfg(feature = "android")]
pub mod android;
pub mod core;
#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "macos")]
pub mod macos;
#[cfg(feature = "win")]
pub mod win;

#[cfg(feature = "apple-secure-enclave")]
pub mod apple_secure_enclave;

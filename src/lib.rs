pub mod common;
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "hsm")]
pub mod hsm;
#[cfg(test)]
mod tests;
#[cfg(feature = "tpm")]
pub mod tpm;
#[cfg(feature = "nks")]
pub mod nks;

pub use common::{error::SecurityModuleError, factory::SecModules};
#[cfg(feature = "ffi")]
pub use ffi::factory::{secmodules_free_instance, secmodules_get_instance};

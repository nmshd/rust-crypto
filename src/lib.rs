#![doc = include_str!("./README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(
    rust_2024_incompatible_pat,
    rust_2024_prelude_collisions,
    clippy::suspicious,
    clippy::perf,
    clippy::cargo
)]
#![deny(clippy::correctness)]
//#![allow(dead_code)]

/// Public module holding the API of the library and common structs.
pub mod common;
pub(crate) mod provider;
pub(crate) mod storage;
#[cfg(test)]
mod tests;

/// Exports structs and functions needed for using the library.
pub mod prelude;

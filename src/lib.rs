//! `cryptolayer` is meant as a library interfacing with secure elements of different operating systems.
//!
//! # Providers
//!
//! | Provider Name                   | Sign and Verify       | Encrypt and Decrypt       | DH Exchange | Import Key | Import Key Pair | Import Public Key | Export Key | Export Private Key | Export Public Key |
//! | ------------------------------- | --------------------- | ------------------------- | ----------- | ---------- | --------------- | ----------------- | ---------- | ------------------ | ----------------- |
//! | STUB_PROVIDER                   | ⬜                    | ⬜                        | ⬜          | ⬜         | ⬜              | ⬜                | ⬜         | ⬜                 | ⬜                |
//! | ANDROID_PROVIDER                | ✅                    | ✅                        | ✅          | ⬜         | ⬜              | ⬜                | ⬜         | ⬜                 | ✅                |
//! | ANDROID_PROVIDER_SECURE_ELEMENT | ✅                    | ✅                        | ✅          | ⬜         | ⬜              | ⬜                | ⬜         | ⬜                 | ✅                |
//! | APPLE_SECURE_ENCLAVE            | ✅                    | ⬜                        | ⬜          | ⬜         | ⬜              | ⬜                | ⬜         | ⬜                 | ✅                |
//! | SoftwareProvider                | ✅                    | ✅                        | ✅          | ✅         | ✅              | ✅                | ⬜         | ✅                 | ✅                |
//!
//!

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

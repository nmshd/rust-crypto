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
//! | SoftwareProvider                | ✅                    | ✅                        | ✅          | ✅         | ✅              | ✅                | ⬜         | ⬜                 | ✅                |
//!
//!

/// Public module holding the API of the library and common structs.
pub mod common;
#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "hsm")]
pub mod hsm;
#[cfg(feature = "nks")]
pub mod nks;
#[cfg(feature = "software")]
pub(crate) mod software;
pub(crate) mod storage;
pub(crate) mod stub;
#[cfg(test)]
mod tests;
pub(crate) mod tpm;

/// Exports structs and functions needed for using the library.
pub mod prelude;

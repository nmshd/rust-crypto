use serde::{Deserialize, Serialize};
use std::cmp::{Eq, PartialEq};
use std::hash::Hash;
use zeroize::Zeroize;

use strum::{EnumString, IntoStaticStr};

/// Represents the available encryption algorithms.
///
/// This enum provides a C-compatible representation of different encryption
/// methods supported by the system, including asymmetric algorithms like RSA and ECC.
/// It is designed to be extensible, allowing for the addition
/// of more encryption algorithms in the future.
///
/// # Note
///
/// This enum uses `#[repr(C)]` to ensure that it has the same memory layout as a C enum,
/// facilitating interfacing with C code or when ABI compatibility is required.
/// flutter_rust_bridge:non_opaque
#[repr(C)]
#[derive(
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Default,
    EnumString,
    IntoStaticStr,
)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum AsymmetricKeySpec {
    RSA1024,
    RSA2048,
    RSA3072,
    RSA4096,
    RSA8192,
    #[default]
    P256,
    P384,
    P521,
    /// `secp256k1` curve, commonly used in blockchain technologies.
    Secp256k1,
    /// Brainpool `P256r1` curve.
    BrainpoolP256r1,
    /// Brainpool `P384r1` curve.
    BrainpoolP384r1,
    /// Brainpool `P512r1` curve.
    BrainpoolP512r1,
    /// Brainpool `P638` curve.
    BrainpoolP638,
    /// `Curve25519`, popular for its security and performance.
    Curve25519,
    /// `Curve448`, known for high security and efficiency.
    Curve448,
    /// `FRP256v1`, a French curve providing strong security and performance.
    Frp256v1,
}

/// Represents the available cipher algorithms.
///
/// This enum provides a C-compatible representation of various algorithms supported,
/// including `AES`, `ChaCha20` variants, `Triple DES`, `DES`, `RC2`, and `Camellia`. Some algorithms can be configured with specific modes of operation and key sizes.
/// It is designed for flexibility, allowing for easy extension to include additional cipher algorithms.
/// Stream ciphers encrypt plaintext one bit or byte at a time, offering different security and performance characteristics compared to block ciphers.
/// `XChaCha20` is the recommended stream cipher for new applications due to its strong security profile.
///
/// # Note
///
/// Marked with `#[repr(C)]` to ensure it has the same memory layout as a C enum,
/// facilitating ABI compatibility and interfacing with C code.
/// flutter_rust_bridge:non_opaque
#[repr(C)]
#[derive(
    Clone,
    Debug,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Default,
    EnumString,
    IntoStaticStr,
    Zeroize,
)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum Cipher {
    AesGcm128,
    #[default]
    AesGcm256,
    AesCbc128,
    AesCbc256,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Cipher {
    /// Returns the key size in bytes.
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::AesCbc128 | Self::AesGcm128 => 16,
            Self::AesCbc256
            | Self::AesGcm256
            | Self::ChaCha20Poly1305
            | Self::XChaCha20Poly1305 => 32,
        }
    }

    pub(crate) fn iv_len(&self) -> usize {
        match self {
            Self::AesCbc128
            | Self::AesGcm128
            | Self::AesCbc256
            | Self::AesGcm256
            | Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }
}

use super::KeyBits;
use serde::{Deserialize, Serialize};
use std::cmp::{Eq, PartialEq};
use std::hash::Hash;

/// Represents the available encryption algorithms.
///
/// This enum provides a C-compatible representation of different encryption
/// methods supported by the system, including asymmetric algorithms like RSA and ECC.
/// It is designed to be extensible, allowing for the addition
/// of more encryption algorithms in the future.
///
/// # Examples
///
/// Basic usage for RSA (assuming `RsaBits` is defined):
///
/// ```
/// use tpm_poc::common::crypto::algorithms::{KeyBits, encryption::AsymmetricEncryption};
///
/// let encryption_method = AsymmetricEncryption::Rsa(KeyBits::Bits2048);
/// ```
///
/// Basic usage for ECC:
///
/// ```
/// use tpm_poc::common::crypto::algorithms::encryption::{AsymmetricEncryption, EccSchemeAlgorithm, EccCurves};
///
/// let encryption_method = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Secp256k1));
/// ```
///
/// # Note
///
/// This enum uses `#[repr(C)]` to ensure that it has the same memory layout as a C enum,
/// facilitating interfacing with C code or when ABI compatibility is required.

#[repr(C)]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum AsymmetricKeySpec {
    /// RSA encryption with selectable key sizes.
    ///
    /// Allows specifying the key size for RSA encryption through the `KeyBits` enum,
    /// supporting various standard key lengths for different security needs. RSA is widely used
    /// for secure data transmission and is known for its simplicity and strong security properties,
    /// provided a sufficiently large key size is used.
    Rsa(KeyBits),

    /// Represents Elliptic Curve Cryptography (ECC) encryption.
    ///
    /// ECC offers encryption methods based on elliptic curves over finite fields,
    /// potentially including various algorithms and curves such as P-256, P-384, and others.
    /// ECC is known for providing the same level of security as RSA but with smaller key sizes,
    /// leading to faster computations and lower power consumption.
    Ecc {
        scheme: EccSigningScheme,
        curve: EccCurve,
    },
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EccSigningScheme {
    /// ECDSA: Elliptic Curve Digital Signature Algorithm.
    EcDsa,
    /// ECDAA: Elliptic Curve Direct Anonymous Attestation.
    EcDaa,
    /// EC-Schnorr: A Schnorr signature scheme variant using elliptic curves.
    EcSchnorr,
}

/// Specifies the curve types for Elliptic Curve Digital Signature Algorithm (ECDSA).
///
/// Lists the supported elliptic curve specifications for ECDSA, affecting security and performance.
/// Includes both NIST P-curves and others like secp256k1 and Brainpool curves.
///
/// # Examples
///
/// Selecting an ECDSA curve:
///
/// ```
/// use tpm_poc::common::crypto::algorithms::encryption::EccCurve;
///
/// let curve_type = EccCurve::Secp256k1;
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EccCurve {
    /// NIST P-256 curve.
    P256,
    /// NIST P-384 curve.
    P384,
    /// NIST P-521 curve.
    P521,
    /// secp256k1 curve, commonly used in blockchain technologies.
    Secp256k1,
    /// Brainpool P256r1 curve.
    BrainpoolP256r1,
    /// Brainpool P384r1 curve.
    BrainpoolP384r1,
    /// Brainpool P512r1 curve.
    BrainpoolP512r1,
    /// Brainpool P638 curve.
    BrainpoolP638,
    /// Curve25519, popular for its security and performance.
    #[default]
    Curve25519,
    /// Curve448, known for high security and efficiency.
    Curve448,
    /// FRP256v1, a French curve providing strong security and performance.
    Frp256v1,
}

/// Represents the available cipher algorithms.
///
/// This enum provides a C-compatible representation of various algorithms supported,
/// including AES, ChaCha20 variants, Triple DES, DES, RC2, and Camellia. Some algorithms can be configured with specific modes of operation and key sizes.
/// It is designed for flexibility, allowing for easy extension to include additional cipher algorithms.
/// Stream ciphers encrypt plaintext one bit or byte at a time, offering different security and performance characteristics compared to block ciphers.
/// XChaCha20 is the recommended stream cipher for new applications due to its strong security profile.
///
/// # Examples
///
/// Using `Cipher` with AES in CBC mode and a 256-bit key:
///
/// ```
/// use tpm_poc::common::crypto::algorithms::{KeyBits,encryption::{Cipher, SymmetricMode}};
///
/// fn main() {
///     let cipher = Cipher::Aes(SymmetricMode::Cbc, KeyBits::Bits256);
/// }
/// ```
///
/// Using `Cipher` with ChaCha20:
///
/// ```
/// use tpm_poc::common::crypto::algorithms::encryption::Cipher;
///
/// fn main() {
///     let cipher = Cipher::Chacha20;
/// }
/// ```
///
/// # Note
///
/// Marked with `#[repr(C)]` to ensure it has the same memory layout as a C enum,
/// facilitating ABI compatibility and interfacing with C code.
#[repr(C)]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    /// AES (Advanced Encryption Standard) block cipher with selectable key sizes and modes.
    Aes(SymmetricMode, KeyBits),
    /// Triple DES block cipher, either in two-key or three-key configurations.
    TripleDes(TripleDesNumKeys),
    /// DES (Data Encryption Standard) block cipher, now considered insecure for many applications.
    Des,
    /// RC2 block cipher with selectable key sizes.
    Rc2(Rc2KeyBits),
    /// Camellia block cipher with selectable key sizes.
    Camellia(SymmetricMode, KeyBits),
    /// RC4 stream cipher.
    ///
    /// Once widely used, RC4 is now considered insecure due to vulnerabilities that have
    /// been discovered over time. It is included here for legacy support and should not
    /// be used for new applications requiring secure encryption.
    Rc4,
    /// ChaCha20 stream cipher.
    ///
    /// Provides strong security and high performance, making it suitable for a wide
    /// range of modern applications. ChaCha20 is recommended for use when a secure and
    /// efficient stream cipher is required.
    Chacha20(ChCha20Mode),
}

impl Default for Cipher {
    fn default() -> Self {
        Self::Aes(SymmetricMode::Gcm, KeyBits::Bits256)
    }
}

/// Specifies the modes of operation for symmetric block ciphers.
///
/// This enum lists the supported modes of operation, such as GCM, CCM, ECB, CBC, CFB, OFB, and CTR.
/// These modes determine how block ciphers process plaintext and ciphertext, affecting security and performance characteristics.
///
/// # Examples
///
/// Selecting AES in GCM mode:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::encryption::SymmetricMode;
///
/// let mode = SymmetricMode::Gcm;
/// ```
///
/// # Note
///
/// `#[repr(C)]` attribute is used for C compatibility.
#[repr(C)]
#[derive(Clone, Debug, Default, Copy, PartialEq, Eq, Hash)]
pub enum SymmetricMode {
    /// AES in Galois/Counter Mode (GCM) with selectable key sizes.
    /// GCM is preferred for its performance and security, providing both encryption and authentication.
    #[default]
    Gcm,

    /// AES in Counter with CBC-MAC (CCM) mode with selectable key sizes.
    /// CCM combines counter mode encryption with CBC-MAC authentication, suitable for constrained environments.
    Ccm,

    /// AES in Electronic Codebook (ECB) mode.
    /// ECB encrypts each block of data independently. Due to its deterministic nature, it's considered insecure for most uses.
    Ecb,

    /// AES in Cipher Block Chaining (CBC) mode.
    /// CBC mode introduces dependencies between blocks for better security but requires proper IV management.
    Cbc,

    /// AES in Cipher Feedback (CFB) mode.
    /// CFB mode turns AES into a stream cipher, allowing for encryption of partial blocks. It's useful for streaming data.
    Cfb,

    /// AES in Output Feedback (OFB) mode.
    /// OFB mode also converts AES into a stream cipher but generates keystream blocks independently of the plaintext.
    Ofb,

    /// AES in Counter (CTR) mode.
    /// CTR mode encrypts a sequence of counters, offering high throughput and parallelization capabilities.
    Ctr,
}

/// Specifies the number of keys used in Triple DES configurations.
///
/// This enum provides options for two-key (Ede2) and three-key (Ede3) Triple DES configurations.
/// The choice between two-key and three-key configurations affects the security level and performance of the encryption process.
///
/// # Examples
///
/// Selecting a Triple DES configuration with three keys:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::encryption::TripleDesNumKeys;
///
/// let des_config = TripleDesNumKeys::Tdes3;
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility.
#[repr(C)]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum TripleDesNumKeys {
    /// Two-key Triple DES, using two different keys for encryption.
    Tdes2,
    /// Three-key Triple DES, providing enhanced security with three different keys.
    Tdes3,
}

/// Specifies the key sizes for the RC2 block cipher.
///
/// This enum lists the supported key sizes for RC2, such as 40, 64, and 128 bits.
/// The selection of key size impacts the security and compatibility of the encryption process.
///
/// # Examples
///
/// Selecting an RC2 key size of 128 bits:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::encryption:: Rc2KeyBits;
///
/// let key_size = Rc2KeyBits::Rc2_128;
/// ```
///
/// # Note
///
/// Marked with `#[repr(C)]` to ensure compatibility with C-based environments.
#[repr(C)]
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum Rc2KeyBits {
    /// RC2 with a 40-bit key.
    Rc2_40,
    /// RC2 with a 64-bit key.
    Rc2_64,
    /// RC2 with a 128-bit key, offering the highest level of security among the options.
    Rc2_128,
}

/// Specifies ChaCha20 Variant.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub enum ChCha20Mode {
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

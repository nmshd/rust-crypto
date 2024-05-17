use super::KeyBits;
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Debug, Copy)]
pub enum AsymmetricEncryption {
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
    Ecc(EccSchemeAlgorithm),
}

impl Default for AsymmetricEncryption {
    fn default() -> Self {
        Self::Ecc(Default::default())
    }
}

impl AsymmetricEncryption {
    /// Retrieves the RSA key size if the asymmetric encryption method is RSA.
    ///
    /// # Returns
    ///
    /// An `Option<KeyBits>` representing the key size of the RSA encryption. Returns `None`
    /// if the encryption method is not RSA.
    pub fn rsa_key_bits(&self) -> Option<KeyBits> {
        match self {
            AsymmetricEncryption::Rsa(key_bits) => Some(*key_bits),
            _ => None,
        }
    }

    /// Retrieves the ECC scheme algorithm if the asymmetric encryption method is ECC.
    ///
    /// This method extracts the specific ECC scheme algorithm used, such as ECDSA, ECDH, etc.
    ///
    /// # Returns
    ///
    /// An `Option<EccSchemeAlgorithm>` representing the ECC scheme. Returns `None`
    /// if the encryption method is not ECC.
    pub fn ecc_scheme(&self) -> Option<EccSchemeAlgorithm> {
        match self {
            AsymmetricEncryption::Ecc(ecc_scheme) => Some(*ecc_scheme),
            _ => None,
        }
    }

    /// Retrieves the elliptic curve used if the asymmetric encryption method is ECC.
    ///
    /// For ECC schemes that specify a curve, this method returns the curve being used. It supports
    /// multiple ECC schemes and their associated curves.
    ///
    /// # Returns
    ///
    /// An `Option<EccCurves>` representing the elliptic curve used. Returns `None`
    /// if the encryption method is not ECC or if the ECC scheme does not specify a curve.
    pub fn ecc_curve(&self) -> Option<EccCurves> {
        match self {
            AsymmetricEncryption::Ecc(ecc_scheme) => match ecc_scheme {
                EccSchemeAlgorithm::EcDsa(curve) => Some(*curve),
                EccSchemeAlgorithm::EcDh(curve) => Some(*curve),
                EccSchemeAlgorithm::EcDaa(curve) => Some(*curve),
                EccSchemeAlgorithm::Sm2(curve) => Some(*curve),
                EccSchemeAlgorithm::EcSchnorr(curve) => Some(*curve),
                EccSchemeAlgorithm::EcMqv(curve) => Some(*curve),
                EccSchemeAlgorithm::Null => None,
            },
            _ => None,
        }
    }
}

/// Enum representing the ECC scheme interface type.
///
/// Defines various algorithms that can be used in conjunction with Elliptic Curve Cryptography (ECC),
/// including signature schemes, key exchange protocols, and more. This allows for flexible cryptographic
/// configurations tailored to different security requirements and performance constraints.
///
/// # Examples
///
/// Selecting an ECC scheme:
///
/// ```
/// use tpm_poc::common::crypto::algorithms::encryption::EccSchemeAlgorithm;
/// use tpm_poc::common::crypto::algorithms::encryption::EccCurves;
///
/// let scheme = EccSchemeAlgorithm::EcDsa(EccCurves::Secp256k1);
/// ```
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EccSchemeAlgorithm {
    /// ECDSA: Elliptic Curve Digital Signature Algorithm.
    EcDsa(EccCurves),
    /// ECDH: Elliptic Curve Diffie-Hellman for key agreement.
    EcDh(EccCurves),
    /// ECDAA: Elliptic Curve Direct Anonymous Attestation.
    EcDaa(EccCurves),
    /// SM2: A Chinese cryptographic standard for digital signatures and key exchange.
    Sm2(EccCurves),
    /// EC-Schnorr: A Schnorr signature scheme variant using elliptic curves.
    EcSchnorr(EccCurves),
    /// ECMQV: Elliptic Curve Menezes-Qu-Vanstone, a key agreement scheme.
    EcMqv(EccCurves),
    /// Null: A placeholder or default value indicating no ECC scheme.
    Null,
}

impl Default for EccSchemeAlgorithm {
    fn default() -> Self {
        Self::EcDsa(EccCurves::Curve25519)
    }
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
/// use tpm_poc::common::crypto::algorithms::encryption::EccCurves;
///
/// let curve_type = EccCurves::Secp256k1;
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EccCurves {
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

/// Represents the available block cipher algorithms.
///
/// This enum provides a C-compatible representation of various block cipher algorithms supported,
/// including AES, Triple DES, DES, RC2, and Camellia. Each algorithm can be configured with specific modes of operation and key sizes.
/// It is designed for flexibility, allowing for easy extension to include additional block cipher algorithms.
///
/// # Examples
///
/// Using `BlockCiphers` with AES in CBC mode and a 256-bit key:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::{KeyBits,encryption::{BlockCiphers, SymmetricMode}};
///
/// let cipher = BlockCiphers::Aes(SymmetricMode::Cbc, KeyBits::Bits256);
/// ```
///
/// Using `BlockCiphers` with Triple DES in EDE3 mode:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::encryption::{BlockCiphers, TripleDesNumKeys};
///
/// let cipher = BlockCiphers::TripleDes(TripleDesNumKeys::Tdes3);
/// ```
///
/// # Note
///
/// Marked with `#[repr(C)]` to ensure it has the same memory layout as a C enum,
/// facilitating ABI compatibility and interfacing with C code.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum BlockCiphers {
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
}

impl Default for BlockCiphers {
    fn default() -> Self {
        Self::Aes(SymmetricMode::Gcm, KeyBits::Bits4096)
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
#[derive(Clone, Debug, Default, Copy)]
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
#[derive(Clone, Debug, Copy)]
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
#[derive(Clone, Debug, Copy)]
pub enum Rc2KeyBits {
    /// RC2 with a 40-bit key.
    Rc2_40,
    /// RC2 with a 64-bit key.
    Rc2_64,
    /// RC2 with a 128-bit key, offering the highest level of security among the options.
    Rc2_128,
}

/// Represents the available stream cipher algorithms.
///
/// This enum provides a C-compatible representation of stream cipher algorithms such as RC4 and ChaCha20.
/// Stream ciphers encrypt plaintext one bit or byte at a time, offering different security and performance characteristics compared to block ciphers.
/// ChaCha20 is recommended for new applications due to its strong security profile.
///
/// # Examples
///
/// Using ChaCha20 stream cipher:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::encryption::StreamCiphers;
///
/// let cipher = StreamCiphers::Chacha20;
/// ```
///
/// # Note
///
/// `#[repr(C)]` attribute is used for C compatibility, important for interoperability with C-based systems.
#[repr(C)]
#[derive(Clone)]
pub enum StreamCiphers {
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
    Chacha20,
}

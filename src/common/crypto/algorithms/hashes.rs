/// Represents the available hashing algorithms.
///
/// This enum provides a C-compatible representation of various hashing algorithms,
/// including both historically significant and modern, secure algorithms.
///
/// When choosing a hashing algorithm, consider its security level and known vulnerabilities.
/// Algorithms like SHA-1, MD2, MD4, and MD5 are considered insecure for most cryptographic
/// purposes due to practical collision attacks and should be avoided for new applications.
/// Prefer using more secure algorithms like SHA-2 or SHA-3 for cryptographic purposes.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum Hash {
    /// SHA-1 hashing algorithm.
    ///
    /// Considered insecure for most cryptographic purposes now due to vulnerabilities
    /// that allow for practical collision attacks.
    Sha1,
    /// SHA-2 family of hashing algorithms with selectable digest sizes.
    Sha2(Sha2Bits),
    /// SHA-3 family of hashing algorithms, also known as Keccak, with selectable digest sizes.
    Sha3(Sha3Bits),
    /// MD2 hashing algorithm.
    ///
    /// Considered cryptographically broken and unsuitable for further use due to significant
    /// vulnerabilities.
    Md2,
    /// MD4 hashing algorithm.
    ///
    /// Faster but less secure than MD5; considered broken due to vulnerabilities to collision attacks.
    Md4,
    /// MD5 hashing algorithm.
    ///
    /// Widely used historically but can no longer be considered secure against collision attacks,
    /// despite its continued use in non-cryptographic contexts like checksums.
    Md5,
    /// RIPEMD-160 hashing algorithm.
    ///
    /// Designed to be a secure alternative to MD4 and MD5. It offers a good balance
    /// of security for applications requiring a hash function more resilient to the
    /// vulnerabilities affecting earlier Message Digest algorithms.
    Ripemd160,
}

impl Default for Hash {
    fn default() -> Self {
        Self::Sha2(Sha2Bits::Sha512)
    }
}

/// Specifies the digest sizes for the SHA-2 family of hashing algorithms.
///
/// This enum lists the supported digest sizes for SHA-2, providing a range of options
/// for different security and performance needs. The larger the digest size, the higher
/// the security level and collision resistance, but with a potential decrease in performance.
/// Selecting the appropriate digest size depends on the specific requirements of the application,
/// balancing security against computational overhead.
///
/// # Examples
///
/// Selecting a SHA-2 digest size:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::hashes::Sha2Bits;
///
/// let digest_size = Sha2Bits::Sha512;
/// ```
///
/// # Note
///
/// `#[repr(C)]` attribute is used for C compatibility, facilitating interoperability with C-based systems.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum Sha2Bits {
    /// 224-bit digest size.
    Sha224,
    /// 256-bit digest size, commonly used for its balance of security and performance.
    Sha256,
    /// 384-bit digest size.
    Sha384,
    /// 512-bit digest size, offering high security for sensitive applications.
    Sha512,
    /// 224-bit digest size variant of SHA-512, designed for compatibility with SHA-224.
    Sha512_224,
    /// 256-bit digest size variant of SHA-512, optimized for security and efficiency.
    Sha512_256,
}

/// Implements the `From` trait to convert a `u32` value to the corresponding `Sha2Bits` variant.
///
/// This allows for easy conversion from integer values to the enum variants, which can be useful
/// when working with external data sources or APIs that represent digest sizes as integers.
impl From<u32> for Sha2Bits {
    fn from(value: u32) -> Self {
        match value {
            224 => Self::Sha224,
            256 => Self::Sha256,
            384 => Self::Sha384,
            512 => Self::Sha512,
            _ => unimplemented!(),
        }
    }
}

/// Implements the `From` trait to convert a `Sha2Bits` variant to its corresponding `u32` value.
///
/// This can be useful when working with APIs or systems that expect digest sizes as integer values
/// instead of enum variants.
impl From<Sha2Bits> for u32 {
    fn from(value: Sha2Bits) -> Self {
        match value {
            Sha2Bits::Sha224 => 224,
            Sha2Bits::Sha256 => 256,
            Sha2Bits::Sha384 => 384,
            Sha2Bits::Sha512 => 512,
            _ => unimplemented!(),
        }
    }
}

/// Specifies the digest sizes for the SHA-3 family of hashing algorithms.
///
/// SHA-3, also known as Keccak, offers a range of digest sizes to accommodate various
/// security levels and performance requirements. As a newer standard compared to SHA-2,
/// SHA-3 introduces a different cryptographic design that is resilient against many of the
/// vulnerabilities that affect older hashing algorithms. Choosing the correct digest size
/// allows developers to optimize for security and efficiency based on their specific needs.
/// A larger digest size generally provides higher security and collision resistance but may
/// come with a performance trade-off.
///
/// # Examples
///
/// Selecting a SHA-3 digest size:
///
/// ```rust
/// use tpm_poc::common::crypto::algorithms::hashes::Sha3Bits;
///
/// let digest_size = Sha3Bits::Sha3_384;
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility, important for interoperability with C-based systems.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum Sha3Bits {
    /// 224-bit digest size for SHA-3.
    Sha3_224,
    /// 256-bit digest size for SHA-3
    Sha3_256,
    /// 384-bit digest size for SHA-3
    Sha3_384,
    /// 512-bit digest size for SHA-3
    Sha3_512,
}

/// Implements the `From` trait to convert a `u32` value to the corresponding `Sha3Bits` variant.
///
/// This allows for easy conversion from integer values to the enum variants, which can be useful
/// when working with external data sources or APIs that represent digest sizes as integers.
impl From<u32> for Sha3Bits {
    fn from(value: u32) -> Self {
        match value {
            224 => Self::Sha3_224,
            256 => Self::Sha3_256,
            384 => Self::Sha3_384,
            512 => Self::Sha3_512,
            _ => unimplemented!(),
        }
    }
}

/// Implements the `From` trait to convert a `Sha3Bits` variant to its corresponding `u32` value.
///
/// This can be useful when working with APIs or systems that expect digest sizes as integer values
/// instead of enum variants.
impl From<Sha3Bits> for u32 {
    fn from(value: Sha3Bits) -> Self {
        match value {
            Sha3Bits::Sha3_224 => 224,
            Sha3Bits::Sha3_256 => 256,
            Sha3Bits::Sha3_384 => 384,
            Sha3Bits::Sha3_512 => 512,
        }
    }
}

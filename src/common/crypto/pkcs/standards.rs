/// Represents the various Public Key Infrastructure (PKI) standards.
///
/// This enum provides a C-compatible representation of different PKI standards,
/// including PKCS (Public-Key Cryptography Standards), X.509, and PEM (Privacy-Enhanced Mail).
/// These standards cover a wide range of purposes, from cryptographic keys and certificates
/// storage to secure communication protocols.
///
/// # Examples
///
/// Using `PkiStandards` with PKCS#1:
///
/// ```rust
/// use tpm_poc::common::crypto::pkcs::standards::{PkiStandards, PkcsType};
///
/// let pki_standard = PkiStandards::Pkcs(PkcsType::Pkcs1);
/// ```
///
/// Using `PkiStandards` with X.509 Certificates:
///
/// ```rust
/// use tpm_poc::common::crypto::pkcs::standards::{PkiStandards, X509Type};
///
/// let pki_standard = PkiStandards::X509(X509Type::Certificate);
/// ```
///
/// # Note
///
/// The `#[repr(C)]` attribute ensures C compatibility, making these enums suitable for
/// interfacing with C-based systems. They encompass a broad range of PKI applications,
/// from encryption and digital signatures to certificate management.
#[repr(C)]
pub enum PkiStandards {
    /// PKCS (Public-Key Cryptography Standards) related operations.
    ///
    /// Wraps various PKCS standards, each focusing on different aspects of public-key cryptography.
    Pkcs(PkcsType),
    /// X.509 related operations, including certificates and revocation lists.
    X509(X509Type),
    /// PEM (Privacy-Enhanced Mail) format for storing and sending cryptographic keys and certificates.
    Pem,
}

/// Enumerates the PKCS (Public-Key Cryptography Standards) types.
///
/// Specifies the different PKCS standards, covering a wide array of cryptographic
/// functionalities, including key exchange, encryption, and digital signatures.
///
/// # Examples
///
/// Selecting a PKCS type for RSA cryptography:
///
/// ```rust
/// use tpm_poc::common::crypto::pkcs::standards::PkcsType;
///
/// let pkcs_type = PkcsType::Pkcs1;
/// ```
///
/// # Note
///
/// `#[repr(C)]` attribute for C compatibility.
#[repr(C)]
pub enum PkcsType {
    /// RSA Cryptography Standard.
    Pkcs1,
    /// Diffie-Hellman Key Agreement Standard.
    Pkcs3,
    /// Password-Based Cryptography Standard.
    Pkcs5,
    /// Cryptographic Message Syntax Standard.
    Pkcs7,
    /// Private-Key Information Syntax Standard.
    Pkcs8,
    /// Selected Attribute Types.
    Pkcs9,
    /// Certification Request Syntax Standard.
    Pkcs10,
    /// Cryptographic Token Interface (Cryptoki).
    Pkcs11,
    /// Personal Information Exchange Syntax Standard.
    Pkcs12,
}

/// Enumerates the types within the X.509 standard.
///
/// Specifies the different elements associated with X.509, a standard for creating
/// a public key infrastructure for digital certificates and public-key encryption.
///
/// # Examples
///
/// Selecting an X.509 type for certificates:
///
/// ```rust
/// use tpm_poc::common::crypto::pkcs::standards::X509Type;
///
/// let x509_type = X509Type::Certificate;
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for compatibility with C language standards, facilitating use
/// in systems where interoperability with C is required.
#[repr(C)]
pub enum X509Type {
    /// Represents an X.509 certificate.
    Certificate,
    /// Represents an X.509 Certificate Revocation List (CRL).
    CertificateRevocationList,
    /// Represents an X.509 Certificate Signing Request (CSR).
    CertificateSigningRequest,
}

/// Represents the collection of Object Identifiers (OIDs) used in various cryptographic standards.
///
/// This enum provides a C-compatible representation of OIDs, which uniquely identify
/// algorithms and standards in cryptography. OIDs are used in multiple contexts, including
/// hashing algorithms, public key cryptography, encryption algorithms, key agreement protocols,
/// and certificate extensions.
///
/// # Examples
///
/// Using `ObjectIdentifiers` for RSA encryption:
///
/// ```rust
/// use tpm_poc::common::crypto::pkcs::standards::{ObjectIdentifiers, OidType};
///
/// let oid = ObjectIdentifiers::Oid(OidType::RsaEncryption);
/// ```
///
/// # Note
///
/// The `#[repr(C)]` attribute ensures C compatibility, facilitating the use of these enums
/// in systems where interoperability with C is required. OIDs play a crucial role in the
/// configuration and operation of cryptographic systems, ensuring the correct application
/// of algorithms and standards.
#[repr(C)]
pub enum ObjectIdentifiers {
    /// Container for various cryptographic Object Identifiers (OIDs).
    Oid(OidType),
}

/// Enumerates specific Object Identifier (OID) types across cryptographic functionalities.
///
/// Lists OIDs for hashing algorithms, public key cryptography, encryption algorithms,
/// key agreement protocols, certificate extensions, extended key usage identifiers, and
/// other notable OIDs.
///
/// # Hashing Algorithms
/// - `Sha1WithRsaEncryption`, `Sha256WithRsaEncryption`, etc.
///
/// # Public Key Cryptography
/// - `RsaEncryption`, `EcPublicKey`, `EcdsaWithSha*`
///
/// # Encryption Algorithms
/// - `Aes128Cbc`, `Aes256Gcm`, etc.
///
/// # Key Agreement
/// - `DhPublicNumber`, `EcdhStandardCurves`
///
/// # Certificate Extensions
/// - `SubjectKeyIdentifier`, `ExtendedKeyUsage`, etc.
///
/// # Extended Key Usage OIDs
/// - `ServerAuth`, `ClientAuth`, `CodeSigning`, etc.
///
/// # Other notable OIDs
/// - `Pkix`, `Pkcs7Data`, `Pkcs9EmailAddress`, etc.
///
/// # Examples
///
/// Selecting an OID for AES 256 CBC encryption:
///
/// ```rust
/// use tpm_poc::common::crypto::pkcs::standards::OidType;
///
/// let oid_type = OidType::Aes256Cbc;
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility. Understanding and using the correct OIDs
/// is essential for ensuring cryptographic operations adhere to the intended standards and
/// protocols.
#[repr(C)]
pub enum OidType {
    // Hashing Algorithms
    Sha1WithRsaEncryption,
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
    IdSha1,
    IdSha256,
    IdSha384,
    IdSha512,

    // Public Key Cryptography
    RsaEncryption,
    IdRsaSsaPss,
    EcPublicKey,
    EcdsaWithSha1,
    EcdsaWithSha256,
    EcdsaWithSha384,
    EcdsaWithSha512,

    // Encryption Algorithms
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,

    // Key Agreement
    DhPublicNumber,
    EcdhStandardCurves,
    EcdhSpecifiedCurves,

    // Certificate Extensions
    SubjectKeyIdentifier,
    KeyUsage,
    SubjectAltName,
    BasicConstraints,
    ExtendedKeyUsage,

    // Extended Key Usage OIDs
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    DocumentSigning,

    // Other OIDs
    Pkix,
    Pkcs7Data,
    Pkcs7SignedData,
    Pkcs7EnvelopedData,
    Pkcs7SignedAndEnvelopedData,
    Pkcs7DigestData,
    Pkcs7EncryptedData,
    Pkcs9EmailAddress,
    Pkcs9UnstructuredName,
    Pkcs9ContentType,
    Pkcs9MessageDigest,
    Pkcs9SigningTime,
}

impl OidType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OidType::Sha1WithRsaEncryption => "1.2.840.113549.1.1.5",
            OidType::Sha256WithRsaEncryption => "1.2.840.113549.1.1.11",
            OidType::Sha384WithRsaEncryption => "1.2.840.113549.1.1.12",
            OidType::Sha512WithRsaEncryption => "1.2.840.113549.1.1.13",
            OidType::IdSha1 => "1.3.14.3.2.26",
            OidType::IdSha256 => "2.16.840.1.101.3.4.2.1",
            OidType::IdSha384 => "2.16.840.1.101.3.4.2.2",
            OidType::IdSha512 => "2.16.840.1.101.3.4.2.3",
            OidType::RsaEncryption => "1.2.840.113549.1.1.1",
            OidType::IdRsaSsaPss => "1.2.840.113549.1.1.10",
            OidType::EcPublicKey => "1.2.840.10045.2.1",
            OidType::EcdsaWithSha1 => "1.2.840.10045.4.1",
            OidType::EcdsaWithSha256 => "1.2.840.10045.4.3.2",
            OidType::EcdsaWithSha384 => "1.2.840.10045.4.3.3",
            OidType::EcdsaWithSha512 => "1.2.840.10045.4.3.4",
            OidType::Aes128Cbc => "2.16.840.1.101.3.4.1.2",
            OidType::Aes192Cbc => "2.16.840.1.101.3.4.1.22",
            OidType::Aes256Cbc => "2.16.840.1.101.3.4.1.42",
            OidType::Aes128Gcm => "2.16.840.1.101.3.4.1.6",
            OidType::Aes192Gcm => "2.16.840.1.101.3.4.1.26",
            OidType::Aes256Gcm => "2.16.840.1.101.3.4.1.46",
            OidType::DhPublicNumber => "1.2.840.10046.2.1",
            OidType::EcdhStandardCurves => "1.3.132.0",
            OidType::EcdhSpecifiedCurves => "1.2.840.10045.3.1",
            OidType::SubjectKeyIdentifier => "2.5.29.14",
            OidType::KeyUsage => "2.5.29.15",
            OidType::SubjectAltName => "2.5.29.17",
            OidType::BasicConstraints => "2.5.29.19",
            OidType::ExtendedKeyUsage => "2.5.29.37",
            OidType::ServerAuth => "1.3.6.1.5.5.7.3.1",
            OidType::ClientAuth => "1.3.6.1.5.5.7.3.2",
            OidType::CodeSigning => "1.3.6.1.5.5.7.3.3",
            OidType::DocumentSigning => "1.3.6.1.4.1.311.10.3.12",
            OidType::EmailProtection => "1.3.6.1.5.5.7.3.4",
            OidType::TimeStamping => "1.3.6.1.5.5.7.3.8",
            OidType::OcspSigning => "1.3.6.1.5.5.7.3.9",
            OidType::Pkix => "1.3.6.1.5.5.7",
            OidType::Pkcs7Data => "1.2.840.113549.1.7.1",
            OidType::Pkcs7SignedData => "1.2.840.113549.1.7.2",
            OidType::Pkcs7EnvelopedData => "1.2.840.113549.1.7.3",
            OidType::Pkcs7SignedAndEnvelopedData => "1.2.840.113549.1.7.4",
            OidType::Pkcs7DigestData => "1.2.840.113549.1.7.5",
            OidType::Pkcs7EncryptedData => "1.2.840.113549.1.7.6",
            OidType::Pkcs9EmailAddress => "1.2.840.113549.1.9.1",
            OidType::Pkcs9UnstructuredName => "1.2.840.113549.1.9.2",
            OidType::Pkcs9ContentType => "1.2.840.113549.1.9.3",
            OidType::Pkcs9MessageDigest => "1.2.840.113549.1.9.4",
            OidType::Pkcs9SigningTime => "1.2.840.113549.1.9.5",
        }
    }
}

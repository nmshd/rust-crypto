use crate::common::crypto::{
    algorithms::{
        encryption::{AsymmetricEncryption, BlockCiphers, EccSchemeAlgorithm},
        hashes::{Hash, Sha2Bits},
    },
    KeyUsage,
};
use tracing::instrument;
use windows::{
    core::PCWSTR,
    Win32::Security::Cryptography::{
        BCRYPT_ALG_HANDLE, BCRYPT_ECDH_ALGORITHM, BCRYPT_ECDSA_ALGORITHM, BCRYPT_MD2_ALGORITHM,
        BCRYPT_MD2_ALG_HANDLE, BCRYPT_MD4_ALGORITHM, BCRYPT_MD4_ALG_HANDLE, BCRYPT_MD5_ALGORITHM,
        BCRYPT_MD5_ALG_HANDLE, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA256_ALG_HANDLE, BCRYPT_SHA384_ALGORITHM, BCRYPT_SHA384_ALG_HANDLE,
        BCRYPT_SHA512_ALGORITHM, BCRYPT_SHA512_ALG_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    },
};

pub mod key_handle;
pub mod provider;

/// A TPM-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations in a Windows environment.
///
/// This provider leverages the Windows Cryptography API: Next Generation (CNG) to interact
/// with a Trusted Platform Module (TPM) for operations like signing, encryption, and decryption.
/// It provides a secure and hardware-backed solution for managing cryptographic keys and performing
/// cryptographic operations on Windows platforms.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpmProvider {
    /// A unique identifier for the cryptographic key managed by this provider.
    key_id: String,
    pub(super) key_handle: Option<NCRYPT_KEY_HANDLE>,
    pub(super) handle: Option<NCRYPT_PROV_HANDLE>,
    pub(super) key_algo: Option<AsymmetricEncryption>,
    pub(super) sym_algo: Option<BlockCiphers>,
    pub(super) hash: Option<Hash>,
    pub(super) key_usages: Option<Vec<KeyUsage>>,
}

impl TpmProvider {
    /// Constructs a new `TpmProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    ///
    /// # Returns
    ///
    /// A new instance of `TpmProvider` with the specified `key_id`.
    #[instrument]
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            handle: None,
            key_handle: None,
            key_algo: None,
            sym_algo: None,
            hash: None,
            key_usages: None,
        }
    }
}

/// Converts a `Hash` value to the corresponding Windows API constant for algorithm handles.
///
/// This implementation maps the `Hash` enum variants to the appropriate `BCRYPT_ALG_HANDLE`
/// constants used by the Windows Cryptography API.
impl From<Hash> for BCRYPT_ALG_HANDLE {
    fn from(value: Hash) -> Self {
        match value {
            Hash::Sha2(bits) => match bits {
                Sha2Bits::Sha256 => BCRYPT_SHA256_ALG_HANDLE,
                Sha2Bits::Sha384 => BCRYPT_SHA384_ALG_HANDLE,
                Sha2Bits::Sha512 => BCRYPT_SHA512_ALG_HANDLE,
                _ => unimplemented!(),
            },
            Hash::Md2 => BCRYPT_MD2_ALG_HANDLE,
            Hash::Md4 => BCRYPT_MD4_ALG_HANDLE,
            Hash::Md5 => BCRYPT_MD5_ALG_HANDLE,
            _ => unimplemented!(),
        }
    }
}

/// Converts a `Hash` value to the corresponding Windows API constant for algorithm names.
///
/// This implementation maps the `Hash` enum variants to the appropriate `PCWSTR` constants
/// representing algorithm names used by the Windows Cryptography API.
impl From<Hash> for PCWSTR {
    fn from(value: Hash) -> Self {
        match value {
            Hash::Sha2(bits) => match bits {
                Sha2Bits::Sha256 => BCRYPT_SHA256_ALGORITHM,
                Sha2Bits::Sha384 => BCRYPT_SHA384_ALGORITHM,
                Sha2Bits::Sha512 => BCRYPT_SHA512_ALGORITHM,
                _ => unimplemented!(),
            },
            Hash::Md2 => BCRYPT_MD2_ALGORITHM,
            Hash::Md4 => BCRYPT_MD4_ALGORITHM,
            Hash::Md5 => BCRYPT_MD5_ALGORITHM,
            _ => unimplemented!(),
        }
    }
}

/// Converts an `AsymmetricEncryption` value to the corresponding Windows API constant for algorithm names.
///
/// This implementation maps the `AsymmetricEncryption` enum variants to the appropriate `PCWSTR` constants
/// representing algorithm names used by the Windows Cryptography API.
impl From<AsymmetricEncryption> for PCWSTR {
    fn from(value: AsymmetricEncryption) -> Self {
        match value {
            AsymmetricEncryption::Rsa(_) => BCRYPT_RSA_ALGORITHM,
            AsymmetricEncryption::Ecc(scheme) => match scheme {
                EccSchemeAlgorithm::EcDsa(_) => BCRYPT_ECDSA_ALGORITHM,
                EccSchemeAlgorithm::EcDh(_) => BCRYPT_ECDH_ALGORITHM,
                _ => unimplemented!(),
            },
        }
    }
}

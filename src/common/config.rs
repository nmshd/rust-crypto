use async_std::sync::Mutex;
use std::cmp::{Eq, Ord, PartialEq, PartialOrd};
use std::collections::HashSet;
use std::sync::Arc;

#[cfg(feature = "android")]
use robusta_jni::jni::JavaVM;

use super::crypto::algorithms::{
    encryption::{AsymmetricKeySpec, Cipher},
    hashes::CryptoHash,
};

/// Enum describing the security level of a provider.
///
/// * [SecurityLevel::Hardware]: Provider is hardware backed (tpm, other security chips, StrongBox KeyStore).
/// * [SecurityLevel::Software]: Provder uses the systems software keystore.
/// * [SecurityLevel::Network]: Provider uses a network key store (Hashicorp).
/// * [SecurityLevel::Unsafe]: Provder uses software fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Highest security level
    Hardware = 4,
    Software = 3,
    Network = 2,
    Unsafe = 1,
}

#[derive(Clone, Copy, Debug)]
pub struct KeySpec {
    pub cipher: Cipher,
    pub signing_hash: CryptoHash,
}

#[derive(Clone, Copy, Debug)]
pub struct KeyPairSpec {
    pub asym_spec: AsymmetricKeySpec,
    pub cipher: Option<Cipher>,
    pub signing_hash: CryptoHash,
}

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub max_security_level: SecurityLevel,
    pub min_security_level: SecurityLevel,
    pub supported_ciphers: HashSet<Cipher>,
    pub supported_hashes: HashSet<CryptoHash>,
    pub supported_asym_spec: HashSet<AsymmetricKeySpec>,
}

#[derive(Clone)]
pub enum ProviderImplConfig {
    None,
    #[cfg(feature = "android")]
    Android { vm: Arc<Mutex<JavaVM>> },
}

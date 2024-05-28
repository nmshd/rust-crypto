use std::any::Any;
use std::fmt;
use std::fmt::{Debug, Formatter};
use crate::common::crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers};
use crate::common::traits::module_provider_config::ProviderConfig;
use jni::JavaVM;
use tracing::instrument;

mod interface;
pub mod key_handle;
pub mod provider;

/// A TPM-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations in an Samsung environment. This provider uses the Java Native Interface
/// and the Android Keystore API to access the TPM "Knox Vault" developed by Samsung
#[derive(Clone, Debug)]
#[repr(C)]
pub struct KnoxProvider {}

impl KnoxProvider {
    /// Constructs a new `TpmProvider`.
    ///
    ///
    /// # Returns
    ///
    /// A new instance of `TpmProvider`.
    #[instrument]
    pub fn new() -> Self {
        Self {}
    }
}

///A struct defining the needed values for the create_key() function in provider.rs
///At any time, either a key_algorithm OR a sym_algorithm must be supplied, not both.
/// For hashing operations, SHA-256 is always used since it is the only one available on Knox Vault
// #[derive(Clone)]
pub struct KnoxConfig<'a> {
    pub key_algorithm: Option<AsymmetricEncryption>,
    pub sym_algorithm: Option<BlockCiphers>,
    // pub env: JNIEnv<'a>,
    pub vm: JavaVM
}

impl Debug for KnoxConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnoxConfig")
            .field("key_algorithm", &self.key_algorithm)
            .field("sym_algorithm", &self.sym_algorithm)
            .field("vm", &self.vm)
            .finish()
    }
}

impl ProviderConfig for KnoxConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl KnoxConfig {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
         key_algorithm: Option<AsymmetricEncryption>,
         sym_algorithm: Option<BlockCiphers>,
         // env: JNIEnv<'a>
         vm: JavaVM
    ) -> Box<dyn ProviderConfig> {
        Box::new(Self {
            key_algorithm,
            sym_algorithm,
            vm,
        })
    }
}
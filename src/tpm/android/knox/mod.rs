use std::any::Any;
use std::fmt;
use std::fmt::{Debug, Formatter};
use robusta_jni::jni;
use crate::common::crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers};
use crate::common::crypto::algorithms::hashes::Hash;
use crate::common::traits::module_provider_config::ProviderConfig;
use jni::JNIEnv;
mod interface;
mod key_handle;
mod provider;

///A struct defining the needed values for the create_key() function in provider.rs
///At any time, either a key_algorithm OR a sym_algorithm must be supplied, not both.
/// For hashing operations, SHA-256 is always used since it is the only one available on Knox Vault
#[derive(Clone)]
pub struct KnoxConfig<'a> {
    pub key_algorithm: Option<AsymmetricEncryption>,
    pub sym_algorithm: Option<BlockCiphers>,
    pub env: JNIEnv<'a>
}

impl Debug for KnoxConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KnoxConfig")
            .field("key_algorithm", &self.key_algorithm)
            .field("sym_algorithm", &self.sym_algorithm)
            .field("env", &self.env)
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
    pub fn new<'a>(
         key_algorithm: Option<AsymmetricEncryption>,
         sym_algorithm: Option<BlockCiphers>,
         hash: Hash, //todo: Test if necessary for sym keys
         env: JNIEnv<'a>
    ) -> Box<dyn ProviderConfig> {
        Box::new(Self {
            key_algorithm,
            sym_algorithm,
            env,
        })
    }
}
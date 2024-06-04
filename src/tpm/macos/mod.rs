use crate::common::{crypto::{
    algorithms::{
        encryption::{AsymmetricEncryption, BlockCiphers, /*SymmetricMode*/},
        /*hashes::Hash,*/
    },
    /*KeyUsage,*/
}, traits::module_provider_config::ProviderConfig};
use std::fmt::{Debug, Formatter, Result};
use std::any::Any;

pub mod key_handle;
pub mod provider;
pub mod logger;

// Provider Setup - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
#[derive(Clone, Debug)]
#[repr(C)]
pub struct TpmProvider {
    pub(super) key_id: String, 
    config: Option<SecureEnclaveConfig>
}

impl TpmProvider {
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            config: None
        }
    }
}

// Config Setup - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 


#[derive(Clone)]
pub struct SecureEnclaveConfig {
    pub key_algorithm: Option<AsymmetricEncryption>,
    pub sym_alogorithm: Option<BlockCiphers>,
}

impl SecureEnclaveConfig{
    pub fn new(key_algorithm: Option<AsymmetricEncryption>, sym_alogorithm: Option<BlockCiphers>) -> SecureEnclaveConfig {
        Self {
            key_algorithm, 
            sym_alogorithm: None
        }
    }
}

impl Debug for SecureEnclaveConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("TpmProvider")
            .field("key_algorithm", &self.key_algorithm)
            .field("sym_algorithm", &self.sym_alogorithm)
            .finish()
    }
}


impl ProviderConfig for SecureEnclaveConfig {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Convert Algorithms

// pub enum kSecAttrKeyType{
//     kSecAttrKeyTypeRSA, 
// }

// impl From<AsymmetricEncryption> for kSecAttrKeyType {
//     fn from(value: AsymmetricEncryption) -> Self {
//         match value {
//             AsymmetricEncryption::Rsa(_) => kSecAttrKeyType::kSecAttrKeyTypeRSA ,
//             AsymmetricEncryption::Ecc(_) => todo!(),
//         }
//     }
// }

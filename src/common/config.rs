use std::any::Any;

use super::{
    crypto::algorithms::encryption::{AsymmetricSigningSpec, AsymmetricSpec, BlockCiphers},
    traits::module_provider::ProviderFactory,
};

pub enum SecurityLevel {
    Hardware,
    Software,
    Network,
}

pub struct KeySpec {
    pub id: String,
    pub block_cipher: BlockCiphers,
    pub security_level: SecurityLevel,
    // the key can be provided for loading
    pub key_material: Option<Vec<u8>>,
}

pub struct KeyPairSpec {
    pub id: String,
    pub asym_spec: AsymmetricSigningSpec,
    pub security_level: SecurityLevel,
    // If only the public data is set, the key will be loaded as an external verification key
    pub public_data: Option<Vec<u8>>,
    pub private_data: Option<Vec<u8>>,
}

pub struct DHSpec {
    pub id: String,
    pub persistet: bool,
    pub security_level: SecurityLevel,
    // what kind of symmetric key should be derived
    pub block_cipher: BlockCiphers,
    pub asymetric_spec: AsymmetricSpec,
}

pub struct AlgorithmMetadata {}

pub struct ProviderConfig {
    pub min_security_level: SecurityLevel,
    pub required_algorithms: AlgorithmMetadata,
    pub expected_provider: Option<Box<dyn ProviderFactory + Send>>,
    pub java_env: Option<Box<dyn Any + Send>>,
    pub write_callback: Box<dyn FnMut(String, &[u8]) -> bool + Send>,
    pub read_callback: Box<dyn FnMut(String) -> Option<Vec<u8>> + Send>,
}

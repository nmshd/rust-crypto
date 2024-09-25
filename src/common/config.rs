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
    id: String,
    block_cipher: BlockCiphers,
    security_level: SecurityLevel,
    // the key can be provided for loading
    key_material: Option<Vec<u8>>,
}

pub struct KeyPairSpec {
    id: String,
    asym_spec: AsymmetricSigningSpec,
    security_level: SecurityLevel,
    // If only the public data is set, the key will be loaded as an external verification key
    public_data: Option<Vec<u8>>,
    private_data: Option<Vec<u8>>,
}

pub struct DHSpec {
    id: String,
    persistet: bool,
    security_level: SecurityLevel,
    // what kind of symmetric key should be derived
    block_cipher: BlockCiphers,
    asymetric_spec: AsymmetricSpec,
}

pub struct AlgorithmMetadata;

pub struct ProviderConfig {
    min_security_level: SecurityLevel,
    required_algorithms: AlgorithmMetadata,
    expected_provider: Option<Box<dyn ProviderFactory + Send>>,
    java_env: Option<Box<dyn Any + Send>>,
}

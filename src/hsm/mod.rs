pub mod core;
pub mod nitrokey;
pub mod yubikey;

pub struct ProviderConfig {
    pub key_algorithm: String,
    pub hash: Option<String>,
    pub key_usages: Vec<String>,
}

impl ProviderConfig {
    pub fn new(
        key_algorithm: String,
        sym_algorithm: Option<String>,
        hash: Option<String>,
        key_usages: Vec<String>,
    ) -> Self {
        Self {
            key_algorithm,
            hash,
            key_usages,
        }
    }
}

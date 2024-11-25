use crate::common::{
    config::{
        AllKeysFn, ConfigHandle, DeleteFn, GetFn, KeyPairSpec, ProviderConfig, ProviderImplConfig,
        SecurityLevel, SerializableSpec, StoreFn,
    },
    crypto::algorithms::{
        encryption::{
            AsymmetricKeySpec, ChCha20Mode, Cipher, EccCurve, EccSigningScheme, SymmetricMode,
        },
        hashes::{CryptoHash, Sha2Bits},
        KeyBits,
    },
    error::CalError,
    traits::module_provider::{ProviderFactory, ProviderImplEnum},
};
use pollster::block_on;
use ring::{
    aead,
    signature::{
        EcdsaSigningAlgorithm, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::to_vec;
use std::collections::HashSet;
use storage::{keys::KeyManager, metadata::MetadataDatabase};
use tracing::debug;

pub mod key_handle;
pub mod provider;
pub mod storage;

#[derive(Clone, Debug)]
pub struct SoftwareProviderAdditionalConfig {
    #[cfg(feature = "software-metadata")]
    pub metadata_path: Option<String>,
    #[cfg(feature = "software-keystore")]
    pub keydb_path: Option<String>,
    #[cfg(feature = "software-keystore")]
    pub keydb_pw: Option<String>,
}

#[derive(Default)]
pub(crate) struct SoftwareProviderFactory {}

impl ProviderFactory for SoftwareProviderFactory {
    fn get_name(&self) -> String {
        "SoftwareProvider".to_owned()
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> ProviderConfig {
        let mut supported_asym_specs = HashSet::new();
        supported_asym_specs.insert(AsymmetricKeySpec::Ecc {
            scheme: EccSigningScheme::EcDsa,
            curve: EccCurve::P256,
        });

        let mut supported_hashes = HashSet::new();
        supported_hashes.insert(CryptoHash::Sha2(Sha2Bits::Sha256));
        supported_hashes.insert(CryptoHash::Sha2(Sha2Bits::Sha384));
        supported_hashes.insert(CryptoHash::Sha2(Sha2Bits::Sha512));

        ProviderConfig {
            min_security_level: SecurityLevel::Software,
            max_security_level: SecurityLevel::Software,
            supported_asym_spec: supported_asym_specs,
            supported_ciphers: HashSet::new(),
            supported_hashes,
        }
    }

    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        Into::into(SoftwareProvider::new(impl_config))
    }
}

pub(crate) struct SoftwareProvider {
    impl_config: ProviderImplConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct KeyPairMetadata {
    pub hash: CryptoHash,
}

impl SoftwareProvider {
    pub(crate) fn new(impl_config: ProviderImplConfig) -> Self {
        Self { impl_config }
    }

    /// Generates the default `ProviderImplConfig` based on the provided additional configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - An optional `ConfigHandle` containing additional configuration data.
    /// * `get_fn` - An optional function for retrieving data.
    /// * `store_fn` - An optional function for storing data.
    /// * `delete_fn` - An optional function for deleting data.
    /// * `all_keys_fn` - An optional function for retrieving all keys.
    ///
    /// # Returns
    ///
    /// A `ProviderImplConfig` instance initialized with the provided or default configurations and function closures.
    #[allow(dead_code)]
    pub(crate) fn get_default_config(
        config: Option<ConfigHandle>,
        get_fn: Option<GetFn>,
        store_fn: Option<StoreFn>,
        delete_fn: Option<DeleteFn>,
        all_keys_fn: Option<AllKeysFn>,
    ) -> ProviderImplConfig {
        debug!("Received config: {:?}", config);

        // Ensure that the config is present
        let config_handle = config.expect("Config is None when entering get_default_config!");

        // Attempt to downcast the `AdditionalConfig` to `SoftwareProviderAdditionalConfig`
        let conf_cast = config_handle
            .implementation
            .as_ref()
            .as_any()
            .downcast_ref::<SoftwareProviderAdditionalConfig>();

        debug!("Downcast result: {:?}", conf_cast);

        // Handle the downcast result
        let software_config =
            conf_cast.expect("Failed to downcast to SoftwareProviderAdditionalConfig");

        // Use provided functions or initialize from metadata_db if a path is given (and the field exists)
        #[cfg(feature = "software-metadata")]
        {
            let (get_fn, store_fn, delete_fn, all_keys_fn) = match &software_config.metadata_path {
                Some(metadata_db_path) => {
                    let metadata_db = MetadataDatabase::new(metadata_db_path)
                        .expect("Failed to initialize MetadataDatabase");

                    (
                        get_fn.unwrap_or_else(|| metadata_db.create_get_fn()),
                        store_fn.unwrap_or_else(|| metadata_db.create_store_fn()),
                        delete_fn.unwrap_or_else(|| metadata_db.create_delete_fn()),
                        all_keys_fn.unwrap_or_else(|| metadata_db.create_all_keys_fn()),
                    )
                }
                None => (
                    get_fn.unwrap(),
                    store_fn.unwrap(),
                    delete_fn.unwrap(),
                    all_keys_fn.unwrap(),
                ),
            };

            // Create the ProviderImplConfig instance
            ProviderImplConfig::new(
                None,
                get_fn,
                store_fn,
                delete_fn,
                all_keys_fn,
                Some(config_handle.clone()),
            )
        }

        #[cfg(not(feature = "software-metadata"))]
        {
            let (get_fn, store_fn, delete_fn, all_keys_fn) = (
                get_fn.unwrap(),
                store_fn.unwrap(),
                delete_fn.unwrap(),
                all_keys_fn.unwrap(),
            );

            ProviderImplConfig::new(
                None,
                get_fn,
                store_fn,
                delete_fn,
                all_keys_fn,
                Some(config_handle.clone()),
            )
        }
    }

    #[cfg(feature = "software-keystore")]
    fn save_key(&self, key: String, key_data: &[u8]) -> Result<(), CalError> {
        let config = self
            .impl_config
            .get_additional_config_as::<SoftwareProviderAdditionalConfig>()
            .unwrap();

        let key_manager = KeyManager::new(
            config.keydb_path.as_ref().unwrap(),
            securestore::KeySource::Password(config.keydb_pw.as_ref().unwrap()),
        )
        .unwrap();
        key_manager
            .store_key(&key, key_data)
            .map_err(|err| CalError::failed_operation(err.to_string(), true, None))
    }

    #[cfg(feature = "software-keystore")]
    fn save_key_pair(&self, key: String, key_bytes: &[u8]) -> Result<(), CalError> {
        let config = self
            .impl_config
            .get_additional_config_as::<SoftwareProviderAdditionalConfig>()
            .unwrap();
        let key_manager = KeyManager::new(
            config.keydb_path.as_ref().unwrap(),
            securestore::KeySource::Password(config.keydb_pw.as_ref().unwrap()),
        )
        .unwrap();

        key_manager
            .store_key(&key, key_bytes)
            .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;

        Ok(())
    }

    #[cfg(feature = "software-keystore")]
    fn load_key_from_store(&self, key: String) -> Result<Vec<u8>, CalError> {
        let config = self
            .impl_config
            .get_additional_config_as::<SoftwareProviderAdditionalConfig>()
            .unwrap();
        let key_manager = KeyManager::new(
            config.keydb_path.as_ref().unwrap(),
            securestore::KeySource::Password(config.keydb_pw.as_ref().unwrap()),
        )
        .unwrap();
        Ok(key_manager.retrieve_key(&key).unwrap())
    }

    #[cfg(feature = "software-keystore")]
    fn delete_key_from_store(&self, key: String) -> Result<(), CalError> {
        let config = self
            .impl_config
            .get_additional_config_as::<SoftwareProviderAdditionalConfig>()
            .unwrap();
        let key_manager = KeyManager::new(
            config.keydb_path.as_ref().unwrap(),
            securestore::KeySource::Password(config.keydb_pw.as_ref().unwrap()),
        )
        .unwrap();
        key_manager.delete_key(&key).unwrap();
        Ok(())
    }

    pub fn load_key_metadata(&self, key: String) -> Result<SerializableSpec, CalError> {
        // Execute the asynchronous get_fn and wait for the result
        let serialized_data =
            block_on((self.impl_config.get_fn)(key.clone())).ok_or_else(|| {
                CalError::failed_operation(format!("Key '{}' not found.", key), false, None)
            })?;

        // Deserialize the Vec<u8> into SerializableSpec using serde_json
        serde_json::from_slice(&serialized_data).map_err(|e| {
            CalError::failed_operation(
                format!("Deserialization error for key '{}': {:?}", key, e),
                false,
                Some(e.into()),
            )
        })
    }

    fn save_key_metadata(&self, key: String, key_spec: SerializableSpec) -> Result<(), CalError> {
        match to_vec(&key_spec) {
            Ok(result) => {
                if block_on((self.impl_config.store_fn)(key, result)) {
                    Ok(())
                } else {
                    Err(CalError::failed_operation(
                        "Failed saving metadata with store_fn.".to_owned(),
                        true,
                        None,
                    ))
                }
            }
            Err(e) => Err(CalError::failed_operation(
                "Failed to serialize metadata.".to_owned(),
                false,
                Some(e.into()),
            )),
        }
    }

    #[allow(dead_code)]
    fn delete_key_metadata(&self, key: String) -> Result<(), CalError> {
        block_on((self.impl_config.delete_fn)(key));
        Ok(())
    }
}

impl From<KeyPairSpec> for &'static EcdsaSigningAlgorithm {
    fn from(value: KeyPairSpec) -> Self {
        match value.asym_spec {
            AsymmetricKeySpec::Ecc { scheme, curve } => match (scheme, curve) {
                (EccSigningScheme::EcDsa, EccCurve::P256) => &ECDSA_P256_SHA256_ASN1_SIGNING,
                (EccSigningScheme::EcDsa, EccCurve::P384) => &ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => panic!("Unsupported ECC curve or scheme"),
            },
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<AsymmetricKeySpec> for &'static dyn VerificationAlgorithm {
    fn from(spec: AsymmetricKeySpec) -> Self {
        match spec {
            AsymmetricKeySpec::Ecc { scheme, curve } => match (scheme, curve) {
                (EccSigningScheme::EcDsa, EccCurve::P256) => &ECDSA_P256_SHA256_ASN1,
                (EccSigningScheme::EcDsa, EccCurve::P384) => &ECDSA_P384_SHA256_ASN1,
                _ => panic!("Unsupported ECC curve or scheme"),
            },
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<AsymmetricKeySpec> for &'static EcdsaSigningAlgorithm {
    fn from(spec: AsymmetricKeySpec) -> Self {
        match spec {
            AsymmetricKeySpec::Ecc { scheme, curve } => match (scheme, curve) {
                (EccSigningScheme::EcDsa, EccCurve::P256) => &ECDSA_P256_SHA256_ASN1_SIGNING,
                (EccSigningScheme::EcDsa, EccCurve::P384) => &ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => panic!("Unsupported ECC curve or scheme"),
            },
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<Cipher> for &'static aead::Algorithm {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::Aes(mode, key_bits) => match (mode, key_bits) {
                (SymmetricMode::Gcm, KeyBits::Bits128) => &ring::aead::AES_128_GCM,
                (SymmetricMode::Gcm, KeyBits::Bits256) => &ring::aead::AES_256_GCM,
                _ => panic!("Unsupported AES mode or key size for AEAD"),
            },
            Cipher::Chacha20(mode) => match mode {
                ChCha20Mode::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
                _ => panic!("Unsupported cipher for AEAD"), // Handle other cases or return an error
            },
            _ => panic!("Unsupported cipher"), // Handle other cases or return an error
        }
    }
}

use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use thiserror::Error;

use crate::{
    prelude::{AdditionalConfig, CalError},
    storage::{
        encryption::{
            key_handle::KeyHandleBackend, key_pair_handle::KeyPairHandleBackend, raw::RawBackend,
        },
        StorageField, StorageManagerInitializationError,
    },
};

mod key_handle;
mod key_pair_handle;
mod raw;

#[derive(Debug, Error)]
pub enum EncryptionBackendError {
    #[error("Failed encryption.")]
    Encrypt { source: CalError },
    #[error("Failed decryption.")]
    Decrypt { source: CalError },
    #[error("The cipher text to be decrypted by the storage manager encryption backend does not match what the expected storage field.")]
    WrongStorageField,
    #[error("Failed to get scope.")]
    Scope { source: CalError },
}

#[enum_dispatch]
pub trait EncryptionBackend {
    fn encrypt(&self, data: &[u8]) -> Result<StorageField, EncryptionBackendError>;

    fn decrypt(&self, cipher: StorageField) -> Result<Vec<u8>, EncryptionBackendError>;

    fn scope(&self) -> Result<String, EncryptionBackendError>;
}

#[enum_dispatch(EncryptionBackend)]
#[derive(Debug, Clone)]
pub enum EncryptionBackendExplicit {
    KeyPairHandleBackend,
    KeyHandleBackend,
    RawBackend,
}

impl EncryptionBackendExplicit {
    pub fn new(config: &[AdditionalConfig]) -> Result<Self, StorageManagerInitializationError> {
        Ok(
            config.iter()
            .filter_map(|e| match e {
                AdditionalConfig::StorageConfigSymmetricEncryption(handle) => {
                    Some(Self::from(KeyHandleBackend::new(handle.clone())))
                }
                AdditionalConfig::StorageConfigAsymmetricEncryption(handle) => {
                    Some(Self::from(KeyPairHandleBackend::new(handle.clone())))
                }
                _ => None,
            })
            .at_most_one()
            .map_err(|_| StorageManagerInitializationError::ConflictingProviderImplConfig { 
                description: "Expected either StorageConfigSymmetricEncryption OR StorageConfigAsymmetricEncryption, not both." 
            })?
            .unwrap_or_else(|| Self::from(RawBackend {}))
        )
    }
}

#[cfg(all(test, feature = "software"))]
mod test {
    use std::collections::HashSet;
    use rstest::{fixture, rstest};

    use crate::{
        common::{KeyHandle, KeyPairHandle, Provider},
        prelude::{
            create_provider, AsymmetricKeySpec, Cipher, CryptoHash, KeyPairSpec, KeySpec,
            ProviderConfig, ProviderImplConfig,
        },
    };
    use super::*;

    fn provider() -> Provider {
        let provider_config = ProviderConfig {
            max_security_level: crate::prelude::SecurityLevel::Software,
            min_security_level: crate::prelude::SecurityLevel::Software,
            supported_ciphers: HashSet::from([Cipher::AesGcm256]),
            supported_hashes: HashSet::from([CryptoHash::Sha2_512]),
            supported_asym_spec: HashSet::from([AsymmetricKeySpec::P256]),
        };

        let provider_impl_config = ProviderImplConfig {
            additional_config: vec![],
        };

        create_provider(&provider_config, provider_impl_config).unwrap()
    }

    #[fixture]
    fn key_handle() -> KeyHandle {
        let mut provider = provider();

        let key_spec = KeySpec {
            cipher: Cipher::XChaCha20Poly1305,
            signing_hash: CryptoHash::Sha2_512,
            ephemeral: true,
            non_exportable: false,
        };

        provider.create_key(key_spec).unwrap()
    }

    #[fixture]
    fn key_pair_handle() -> KeyPairHandle {
        let mut provider = provider();

        let key_pair_spec = KeyPairSpec {
            asym_spec: AsymmetricKeySpec::P256,
            cipher: Some(Cipher::AesGcm256),
            signing_hash: CryptoHash::Sha2_512,
            ephemeral: true,
            non_exportable: false,
        };

        provider.create_key_pair(key_pair_spec).unwrap()
    }

    #[rstest]
    #[case::none(vec![])]
    #[case::symmetric(vec![AdditionalConfig::StorageConfigSymmetricEncryption(key_handle())])]
    #[case::asymmetric(vec![AdditionalConfig::StorageConfigAsymmetricEncryption(key_pair_handle())])]
    #[should_panic]
    #[case::symmetric_and_asymmetric_panic(vec![
        AdditionalConfig::StorageConfigSymmetricEncryption(key_handle()),
        AdditionalConfig::StorageConfigAsymmetricEncryption(key_pair_handle()),
    ])]
    fn test_new(#[case] additional_config: Vec<AdditionalConfig>) {
        let _encryption = EncryptionBackendExplicit::new(&additional_config).unwrap();
    }

    #[fixture]
    fn encryption_backend_symmetric() -> EncryptionBackendExplicit {
        let config = vec![AdditionalConfig::StorageConfigSymmetricEncryption(key_handle())];
        EncryptionBackendExplicit::new(&config).unwrap()
    }

    #[fixture]
    fn encryption_backend_asymmetric() -> EncryptionBackendExplicit {
        let config = vec![AdditionalConfig::StorageConfigAsymmetricEncryption(key_pair_handle())];
        EncryptionBackendExplicit::new(&config).unwrap()
    }

    #[fixture]
    fn encryption_backend_raw() -> EncryptionBackendExplicit {
        let config: Vec<AdditionalConfig> = vec![];
        EncryptionBackendExplicit::new(&config).unwrap()
    }

    #[rstest]
    #[case::none(encryption_backend_raw())]
    #[case::symmetric(encryption_backend_symmetric())]
    // #[case::asymmetric(encryption_backend_asymmetric())]
    fn test_encrypt(#[case] backend: EncryptionBackendExplicit) {
        let data = b"Hello World!";
        let _field = backend.encrypt(data).unwrap();
    }

    #[rstest]
    #[case::none(encryption_backend_raw())]
    #[case::symmetric(encryption_backend_symmetric())]
    // #[case::asymmetric(encryption_backend_asymmetric())]
    fn test_encrypt_and_decrypt(#[case] backend: EncryptionBackendExplicit) {
        let data = b"Hello World!".to_vec();
        let field = backend.encrypt(&data).unwrap();
        let decrypted = backend.decrypt(field).unwrap();
        assert_eq!(decrypted, data);
    }

    #[rstest]
    #[case::none_symmetric(encryption_backend_raw(), encryption_backend_symmetric())]
    // #[case::none_asymmetric(encryption_backend_raw(), encryption_backend_asymmetric())]
    #[case::symmetric_none(encryption_backend_symmetric(), encryption_backend_raw())]
    // #[case::symmetric_asymmetric(encryption_backend_symmetric(), encryption_backend_asymmetric())]
    // #[case::asymmetric_none(encryption_backend_asymmetric(), encryption_backend_raw())]
    // #[case::asymmetric_symmetric(encryption_backend_asymmetric(), encryption_backend_symmetric())]
    fn test_fail_on_wrong_encryption_backend(
        #[case] backend_encrypt: EncryptionBackendExplicit,
        #[case] backend_decrypt: EncryptionBackendExplicit,
    ) {
        let data = b"Hello World!".to_vec();
        let field = backend_encrypt.encrypt(&data).unwrap();
        let error = backend_decrypt.decrypt(field).unwrap_err();
        assert!(matches!(error, EncryptionBackendError::WrongStorageField));
    }
}

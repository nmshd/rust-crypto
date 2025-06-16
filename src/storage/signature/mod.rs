use enum_dispatch::enum_dispatch;
use itertools::Itertools;
use thiserror::Error;

use crate::prelude::{AdditionalConfig, CalError};
use crate::storage::signature::dsa::DsaBackend;
use crate::storage::signature::hmac::HmacBackend;
use crate::storage::signature::none::NoneBackend;
use crate::storage::{SignedData, StorageManagerInitializationError};

mod dsa;
mod hmac;
mod none;

#[derive(Debug, Error)]
pub enum SignatureBackendError {
    #[error("Failed to sign data.")]
    Sign { source: CalError },
    #[error("Error occurred during verifying signature.")]
    DuringVerify { source: CalError },
    #[error("Data failed to be verified by signature.")]
    Verify,
    #[error("Wrong signature type. Cannot verify such signature with this signature backend.")]
    WrongSignatureType,
    #[error("Failed to get scope.")]
    Scope { source: CalError },
}

#[enum_dispatch]
pub trait SignatureBackend {
    fn verify(&self, signed_data: SignedData) -> Result<Vec<u8>, SignatureBackendError>;

    fn sign(&self, data: Vec<u8>) -> Result<SignedData, SignatureBackendError>;

    fn scope(&self) -> Result<String, SignatureBackendError>;
}

#[enum_dispatch(SignatureBackend)]
#[derive(Debug, Clone)]
pub enum SignatureBackendExplicit {
    DsaBackend,
    HmacBackend,
    NoneBackend,
}

impl SignatureBackendExplicit {
    pub fn new(config: &[AdditionalConfig]) -> Result<Self, StorageManagerInitializationError> {
        Ok(config
            .iter()
            .filter_map(|e| match e {
                AdditionalConfig::StorageConfigHMAC(handle) => {
                    Some(Self::from(HmacBackend::new(handle.clone())))
                }
                AdditionalConfig::StorageConfigDSA(handle) => {
                    Some(Self::from(DsaBackend::new(handle.clone())))
                }
                _ => None,
            })
            .at_most_one()
            .map_err(
                |_| StorageManagerInitializationError::ConflictingProviderImplConfig {
                    description: "Expected either StorageConfigHMAC OR StorageConfigDSA, not both.",
                },
            )?
            .unwrap_or_else(|| Self::from(NoneBackend {})))
    }
}

#[cfg(test)]
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
            cipher: None,
            signing_hash: CryptoHash::Sha2_512,
            ephemeral: true,
            non_exportable: false,
        };

        provider.create_key_pair(key_pair_spec).unwrap()
    }

    #[rstest]
    #[case::none(vec![])]
    #[case::hmac(vec![AdditionalConfig::StorageConfigHMAC(key_handle())])]
    #[case::dsa(vec![AdditionalConfig::StorageConfigDSA(key_pair_handle())])]
    #[should_panic]
    #[case::hmac_and_dsa_panic(vec![
        AdditionalConfig::StorageConfigHMAC(key_handle()), 
        AdditionalConfig::StorageConfigDSA(key_pair_handle())
    ])]
    fn test_new(#[case] additional_config: Vec<AdditionalConfig>) {
        let _signature = SignatureBackendExplicit::new(&additional_config).unwrap();
    }

    #[rstest]
    #[case::none(vec![])]
    #[case::hmac(vec![AdditionalConfig::StorageConfigHMAC(key_handle())])]
    #[case::dsa(vec![AdditionalConfig::StorageConfigDSA(key_pair_handle())])]
    fn test_sign(#[case] additional_config: Vec<AdditionalConfig>) {
        let signature_backend = SignatureBackendExplicit::new(&additional_config).unwrap();

        let test_data = b"Hello World!".to_vec();

        let _signed_data =  signature_backend.sign(test_data).unwrap();
    }

    #[rstest]
    #[case::none(vec![])]
    #[case::hmac(vec![AdditionalConfig::StorageConfigHMAC(key_handle())])]
    #[case::dsa(vec![AdditionalConfig::StorageConfigDSA(key_pair_handle())])]
    fn test_sign_and_verify(#[case] additional_config: Vec<AdditionalConfig>) {
        let signature_backend = SignatureBackendExplicit::new(&additional_config).unwrap();

        let test_data = b"Hello World!".to_vec();

        let signed_data =  signature_backend.sign(test_data.clone()).unwrap();

        let verified_test_data = signature_backend.verify(signed_data).unwrap();

        assert_eq!(verified_test_data, test_data);
    }
}

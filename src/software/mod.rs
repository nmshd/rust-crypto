use crate::{
    common::{
        config::{ProviderConfig, ProviderImplConfig, SecurityLevel},
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher},
            hashes::CryptoHash,
        },
        error::CalError,
        traits::module_provider::{ProviderFactory, ProviderImplEnum},
    },
    storage::StorageManager,
};
use ring::{
    aead, agreement,
    signature::{
        EcdsaSigningAlgorithm, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    },
};
use serde::{Deserialize, Serialize};

use std::collections::HashSet;

pub(crate) mod key_handle;
pub(crate) mod provider;
// pub(crate) mod storage;

#[derive(Default)]
pub(crate) struct SoftwareProviderFactory {}

impl ProviderFactory for SoftwareProviderFactory {
    fn get_name(&self) -> Option<String> {
        Some("SoftwareProvider".to_owned())
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        let mut supported_asym_specs = HashSet::new();
        supported_asym_specs.insert(AsymmetricKeySpec::P256);
        supported_asym_specs.insert(AsymmetricKeySpec::Curve25519);

        let mut cipher_set = HashSet::new();
        cipher_set.insert(Cipher::AesGcm128);
        cipher_set.insert(Cipher::AesGcm256);
        cipher_set.insert(Cipher::ChaCha20Poly1305);

        let mut supported_hashes = HashSet::new();
        supported_hashes.insert(CryptoHash::Sha2_256);
        supported_hashes.insert(CryptoHash::Sha2_384);
        supported_hashes.insert(CryptoHash::Sha2_512);

        Some(ProviderConfig {
            min_security_level: SecurityLevel::Software,
            max_security_level: SecurityLevel::Software,
            supported_asym_spec: supported_asym_specs,
            supported_ciphers: cipher_set,
            supported_hashes,
        })
    }

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        let storage_manager =
            StorageManager::new(self.get_name().unwrap(), &impl_config.additional_config)?;
        Ok(Into::into(SoftwareProvider {
            impl_config,
            storage_manager,
        }))
    }
}

pub(crate) struct SoftwareProvider {
    impl_config: ProviderImplConfig,
    storage_manager: Option<StorageManager>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct KeyPairMetadata {
    pub hash: CryptoHash,
}

impl From<AsymmetricKeySpec> for &'static dyn VerificationAlgorithm {
    fn from(spec: AsymmetricKeySpec) -> Self {
        match spec {
            AsymmetricKeySpec::P256 => &ECDSA_P256_SHA256_ASN1,
            AsymmetricKeySpec::P384 => &ECDSA_P384_SHA384_ASN1,
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<AsymmetricKeySpec> for &'static EcdsaSigningAlgorithm {
    fn from(spec: AsymmetricKeySpec) -> Self {
        match spec {
            AsymmetricKeySpec::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
            AsymmetricKeySpec::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<Cipher> for &'static aead::Algorithm {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::AesGcm128 => &ring::aead::AES_128_GCM,
            Cipher::AesGcm256 => &ring::aead::AES_256_GCM,
            Cipher::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
            _ => panic!("Unsupported cipher"), // Handle other cases or return an error
        }
    }
}

impl TryFrom<AsymmetricKeySpec> for &'static agreement::Algorithm {
    type Error = CalError;

    fn try_from(spec: AsymmetricKeySpec) -> Result<Self, Self::Error> {
        match spec {
            AsymmetricKeySpec::P256 => Ok(&agreement::ECDH_P256),
            AsymmetricKeySpec::P384 => Ok(&agreement::ECDH_P384),
            AsymmetricKeySpec::Curve25519 => Ok(&agreement::X25519),
            // Handle other variants or return an error
            _ => Err(CalError::failed_operation(
                "Algorithm not supported".to_string(),
                true,
                None,
            )),
        }
    }
}

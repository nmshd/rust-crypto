use std::collections::HashSet;

use async_trait::async_trait;
use security_framework::{
    access_control::{self, ProtectionMode, SecAccessControl},
    item::Location,
    key::{GenerateKeyOptions, KeyType, SecKey},
};

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, EccCurve, EccSigningScheme},
        hashes::{CryptoHash, Sha2Bits},
        KeyBits,
    },
    error::SecurityModuleError,
    traits::module_provider::{ProviderFactory, ProviderImpl},
    KeyPairHandle,
};

use crate::tpm::apple_secure_enclave::key_handle::AppleSecureEnclaveKeyPair;

struct AppleSecureEnclaveFactory {}

#[async_trait]
impl ProviderFactory for AppleSecureEnclaveFactory {
    fn get_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }

    async fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig {
        match impl_config {
            ProviderImplConfig::AppleSecureEnclave {} => {}
            _ => panic!("Invalid ProviderImplConfig supplied."),
        }

        ProviderConfig {
            max_security_level: SecurityLevel::Hardware,
            min_security_level: SecurityLevel::Hardware,
            supported_ciphers: HashSet::new(),
            supported_asym_spec: HashSet::from([AsymmetricKeySpec::Ecc {
                scheme: EccSigningScheme::EcDsa,
                curve: EccCurve::P256,
            }]),
            supported_hashes: HashSet::from([CryptoHash::Sha2(Sha2Bits::Sha256)]),
        }
    }

    async fn create_provider(&self, impl_config: ProviderImplConfig) -> Box<dyn ProviderImpl> {
        Box::new(AppleSecureEnclaveProvider {})
    }
}

#[derive(Debug)]
struct AppleSecureEnclaveProvider {}

#[async_trait]
impl ProviderImpl for AppleSecureEnclaveProvider {
    async fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn load_key(&mut self, key_id: String) -> Result<KeyHandle, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        debug_assert_eq!(
            spec,
            KeyPairSpec {
                asym_spec: AsymmetricKeySpec::Ecc {
                    scheme: EccSigningScheme::EcDsa,
                    curve: EccCurve::P256
                },
                cipher: None,
                signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256)
            }
        );

        let access_controll = match SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        ) {
            Ok(access_control) => access_control,
            Err(e) => return Err(SecurityModuleError::InitializationError(e.to_string())),
        };

        let key_options = GenerateKeyOptions {
            key_type: Some(KeyType::ec()),
            size_in_bits: Some(256),
            label: None,
            token: None,
            location: Some(Location::DataProtectionKeychain),
            access_control: Some(access_controll),
        };

        let sec_key: SecKey = match SecKey::new(&key_options) {
            Ok(sec_key) => sec_key,
            Err(e) => Err(SecurityModuleError::InitializationError(e.to_string())),
        };

        Ok(KeyPairHandle {
            implementation: Box::new(AppleSecureEnclaveKeyPair {
                key_handle: sec_key,
            }),
        })
    }

    async fn load_key_pair(
        &mut self,
        key_id: String,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn import_key(
        &mut self,
        spec: KeySpec,
        data: &[u8],
    ) -> Result<KeyHandle, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    async fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        todo!()
    }

    async fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<DHExchange, SecurityModuleError> {
        Err(SecurityModuleError::UnsupportedAlgorithm)
    }

    fn provider_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }
}

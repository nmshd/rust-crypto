use std::collections::HashSet;

use anyhow::anyhow;
use base64::prelude::*;
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{GenerateKeyOptions, KeyType, SecKey},
};

use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, EccCurve, EccSigningScheme},
        hashes::{CryptoHash, Sha2Bits},
    },
    error::CalError,
    traits::module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
    DHExchange, KeyHandle, KeyPairHandle,
};

use crate::tpm::apple_secure_enclave::{key_handle::AppleSecureEnclaveKeyPair, *};

pub(crate) struct AppleSecureEnclaveFactory {}

impl ProviderFactory for AppleSecureEnclaveFactory {
    fn get_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }

    fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig {
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

    fn create_provider(&self, _impl_config: ProviderImplConfig) -> ProviderImplEnum {
        AppleSecureEnclaveProvider {}.into()
    }
}

#[derive(Debug)]
pub(crate) struct AppleSecureEnclaveProvider {}

impl ProviderImpl for AppleSecureEnclaveProvider {
    fn create_key(&mut self, _spec: KeySpec) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn load_key(&mut self, _key_id: String) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        debug_assert_eq!(
            spec.asym_spec,
            AsymmetricKeySpec::Ecc {
                scheme: EccSigningScheme::EcDsa,
                curve: EccCurve::P256
            }
        );
        debug_assert_eq!(spec.cipher, None);
        debug_assert_eq!(spec.signing_hash, CryptoHash::Sha2(Sha2Bits::Sha256));

        let access_controll = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .err_internal()?;

        let key_options = GenerateKeyOptions {
            key_type: Some(KeyType::ec()),
            size_in_bits: Some(256),
            label: None,
            token: None,
            location: Some(Location::DataProtectionKeychain),
            access_control: Some(access_controll),
        };

        let sec_key: SecKey = SecKey::new(&key_options).err_internal()?;

        Ok(KeyPairHandle {
            implementation: AppleSecureEnclaveKeyPair {
                key_handle: sec_key,
            }
            .into(),
        })
    }

    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        let label = match BASE64_STANDARD.decode(&key_id) {
            Ok(label) => label,
            Err(e) => {
                return Err(CalError::bad_parameter(
                    "Failed decoding base64 string.".to_owned(),
                    false,
                    Some(anyhow!(e)),
                ))
            }
        };

        let search_results: Vec<SearchResult> = match ItemSearchOptions::new()
            .class(ItemClass::key())
            .key_class(KeyClass::private())
            .load_refs(true)
            .application_label(&label)
            .search()
        {
            Ok(search_results) => search_results,
            Err(e) => {
                return Err(CalError::missing_value(
                    "FSecItemCopyMatching failed.".to_owned(),
                    false,
                    Some(anyhow!(e)),
                ))
            }
        };

        let first_search_result: SearchResult = match search_results.into_iter().next() {
            Some(result) => result,
            None => {
                return Err(CalError::missing_value(
                    format!("Failed to find security key with label: {}", &key_id),
                    false,
                    None,
                ))
            }
        };

        let sec_key: SecKey = match first_search_result {
            SearchResult::Ref(reference) => match reference {
                Reference::Key(sec_key) => sec_key,
                _ => {
                    return Err(CalError::missing_value(
                        "Expected a Reference to a Key.".to_owned(),
                        true,
                        None,
                    ))
                }
            },
            _ => {
                return Err(CalError::missing_value(
                    "Expected a Reference.".to_owned(),
                    true,
                    None,
                ))
            }
        };

        Ok(KeyPairHandle {
            implementation: AppleSecureEnclaveKeyPair {
                key_handle: sec_key,
            }
            .into(),
        })
    }

    fn import_key(&mut self, _spec: KeySpec, _data: &[u8]) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn import_key_pair(
        &mut self,
        _spec: KeyPairSpec,
        _public_key: &[u8],
        _private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn import_public_key(
        &mut self,
        _spec: KeyPairSpec,
        _public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn start_ephemeral_dh_exchange(&mut self, _spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    fn provider_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }

    fn get_capabilities(&self) -> ProviderConfig {
        todo!()
    }
}

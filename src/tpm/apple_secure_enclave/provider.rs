use std::collections::HashSet;
use std::fmt;
use std::sync::LazyLock;

use anyhow::anyhow;
use base64::prelude::*;
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{GenerateKeyOptions, KeyType, SecKey},
};

use pollster::block_on;
use serde_json::{from_slice, to_vec};

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

use key_handle::KeyPairMetadata;

static CAPABILITIES: LazyLock<ProviderConfig> = LazyLock::new(|| ProviderConfig {
    max_security_level: SecurityLevel::Hardware,
    min_security_level: SecurityLevel::Hardware,
    supported_ciphers: HashSet::new(),
    supported_asym_spec: HashSet::from([AsymmetricKeySpec::Ecc {
        scheme: EccSigningScheme::EcDsa,
        curve: EccCurve::P256,
    }]),
    supported_hashes: HashSet::from([
        CryptoHash::Sha1,
        CryptoHash::Sha2(Sha2Bits::Sha224),
        CryptoHash::Sha2(Sha2Bits::Sha256),
        CryptoHash::Sha2(Sha2Bits::Sha384),
        CryptoHash::Sha2(Sha2Bits::Sha512),
    ]),
});

fn check_key_pair_spec_for_compatibility(key_spec: &KeyPairSpec) -> Result<(), CalError> {
    if !CAPABILITIES
        .supported_hashes
        .contains(&key_spec.signing_hash)
    {
        return Err(CalError::bad_parameter(
            format!("Signing hash not supported: {:#?}", &key_spec.signing_hash),
            true,
            None,
        ));
    }

    if !CAPABILITIES
        .supported_asym_spec
        .contains(&key_spec.asym_spec)
    {
        return Err(CalError::bad_parameter(
            format!("Asymmetric spec not supported: {:#?}", &key_spec.asym_spec),
            true,
            None,
        ));
    }

    if let Some(cipher) = &key_spec.cipher {
        if !CAPABILITIES.supported_ciphers.contains(&cipher) {
            return Err(CalError::bad_parameter(
                format!("Cipher not supported: {:#?}", &key_spec.cipher),
                true,
                None,
            ));
        }
    }

    Ok(())
}

pub(crate) struct AppleSecureEnclaveFactory {}

impl ProviderFactory for AppleSecureEnclaveFactory {
    fn get_name(&self) -> String {
        "APPLE_SECURE_ENCLAVE".to_owned()
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> ProviderConfig {
        CAPABILITIES.clone()
    }

    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        AppleSecureEnclaveProvider { impl_config }.into()
    }
}

pub(crate) struct AppleSecureEnclaveProvider {
    pub(crate) impl_config: ProviderImplConfig,
}

impl ProviderImpl for AppleSecureEnclaveProvider {
    fn create_key(&mut self, _spec: KeySpec) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn load_key(&mut self, _key_id: String) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        check_key_pair_spec_for_compatibility(&spec)?;

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

        let metadata = KeyPairMetadata {
            hash: spec.signing_hash,
        };

        let key_pair = KeyPairHandle {
            implementation: AppleSecureEnclaveKeyPair {
                key_handle: sec_key,
                metadata: metadata.clone(),
            }
            .into(),
        };

        self.save_key_pair_metadata(key_pair.id()?, metadata)?;

        Ok(key_pair)
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

        let metadata = self.load_key_pair_metadata(key_id)?;

        Ok(KeyPairHandle {
            implementation: AppleSecureEnclaveKeyPair {
                key_handle: sec_key,
                metadata,
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
        CAPABILITIES.clone()
    }
}

impl AppleSecureEnclaveProvider {
    fn save_key_pair_metadata(
        &self,
        key: String,
        metadata: KeyPairMetadata,
    ) -> Result<(), CalError> {
        match to_vec(&metadata) {
            Ok(result) => {
                if block_on((*self.impl_config.store_fn)(key, result)) {
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

    fn load_key_pair_metadata(&self, key: String) -> Result<KeyPairMetadata, CalError> {
        if let Some(data) = block_on((*self.impl_config.get_fn)(key)) {
            match from_slice(&data) {
                Ok(decoded_data) => Ok(decoded_data),
                Err(e) => Err(CalError::failed_operation(
                    "Failed decoding data from get_fn.".to_owned(),
                    false,
                    Some(e.into()),
                )),
            }
        } else {
            Err(CalError::missing_value(
                "Failed loading data for key.".to_owned(),
                false,
                None,
            ))
        }
    }

    fn delete_key_pair_metadata(&self, key: String) {
        block_on((*self.impl_config.delete_fn)(key))
    }
}

impl fmt::Debug for AppleSecureEnclaveProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AppleSecureEnclaveProvider")
    }
}

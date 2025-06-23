use std::collections::HashSet;
use std::sync::LazyLock;

use anyhow::anyhow;
use base64::prelude::*;
use itertools::Itertools;
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    item::{ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult},
    key::{GenerateKeyOptions, KeyType, SecKey},
};
use tracing::instrument;

use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel, Spec},
        crypto::algorithms::{encryption::AsymmetricKeySpec, hashes::CryptoHash},
        error::CalError,
        traits::module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
        DHExchange, KeyHandle, KeyPairHandle,
    },
    storage::{KeyData, StorageManager},
};

use crate::provider::apple_secure_enclave::{key_handle::AppleSecureEnclaveKeyPair, *};

static CAPABILITIES: LazyLock<ProviderConfig> = LazyLock::new(|| ProviderConfig {
    max_security_level: SecurityLevel::Hardware,
    min_security_level: SecurityLevel::Hardware,
    supported_ciphers: HashSet::new(),
    supported_asym_spec: HashSet::from([AsymmetricKeySpec::P256]),
    supported_hashes: HashSet::from([
        CryptoHash::Sha2_224,
        CryptoHash::Sha2_256,
        CryptoHash::Sha2_384,
        CryptoHash::Sha2_512,
    ]),
});

#[instrument(level = "trace")]
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
    fn get_name(&self) -> Option<String> {
        Some("APPLE_SECURE_ENCLAVE".to_owned())
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        Some(CAPABILITIES.clone())
    }

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        let storage_manager =
            StorageManager::new(self.get_name().unwrap(), &impl_config.additional_config)?;

        Ok(AppleSecureEnclaveProvider { storage_manager }.into())
    }
}

#[derive(Debug)]
pub(crate) struct AppleSecureEnclaveProvider {
    pub(crate) storage_manager: Option<StorageManager>,
}

impl ProviderImpl for AppleSecureEnclaveProvider {
    fn create_key(&mut self, _spec: KeySpec) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn load_key(&mut self, _key_id: String) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    #[instrument]
    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        check_key_pair_spec_for_compatibility(&spec)?;
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let access_controll = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .err_internal()?;

        let mut key_options = GenerateKeyOptions::default();
        key_options
            .set_key_type(KeyType::ec())
            .set_size_in_bits(256)
            .set_location(Location::DataProtectionKeychain)
            .set_access_control(access_controll);

        let sec_key: SecKey = SecKey::new(&key_options).err_internal()?;

        let id = match sec_key.application_label() {
            None => Err(CalError::missing_value(
                "kSecAttrApplicationLabel missing for this key".to_owned(),
                false,
                None,
            )),
            Some(bytes) => Ok(BASE64_STANDARD.encode(bytes)),
        }?;

        let storage_data = KeyData {
            id: id.clone(),
            secret_data: None,
            public_data: None,
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        let storage_manager = self.storage_manager.clone().filter(|_| !spec.ephemeral);

        if storage_manager.is_some() {
            self.storage_manager
                .as_mut()
                .unwrap()
                .store(id.clone(), storage_data)?;
        }

        let key_pair = KeyPairHandle {
            implementation: AppleSecureEnclaveKeyPair {
                key_handle: sec_key,
                spec,
                storage_manager,
            }
            .into(),
        };

        Ok(key_pair)
    }

    #[instrument]
    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() {
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot have stored keys".to_owned(),
                true,
                None,
            ));
        }

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

        let spec = match self
            .storage_manager
            .as_ref()
            .unwrap()
            .get(key_id.clone())?
            .spec
        {
            Spec::KeyPairSpec(v) => v,
            Spec::KeySpec(_) => {
                return Err(CalError::failed_operation(
                    "trying to load symmetric key as KeyPair".to_owned(),
                    true,
                    None,
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
                spec,
                storage_manager: self.storage_manager.clone(),
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

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        Some(CAPABILITIES.clone())
    }

    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        if let Some(storage_manager) = self.storage_manager.as_ref() {
            storage_manager
                .get_all_keys()
                .into_iter()
                .process_results(|key_spec_tuple_iter| key_spec_tuple_iter.collect())
                .map_err(|err| {
                    // TODO: Better mapping to CalError.
                    CalError::failed_operation(
                        "At least metadata for one key could not be loaded.",
                        true,
                        Some(anyhow!(err)),
                    )
                })
        } else {
            Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot have stored keys",
                true,
                None,
            ))
        }
    }
}

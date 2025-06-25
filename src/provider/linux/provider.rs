use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use nanoid::rngs::non_secure;
use tss_esapi::{
    structures::{Private, Public},
    traits::{Marshall, UnMarshall},
};

use crate::{
    common::{
        config::Spec,
        error::KeyType,
        traits::module_provider::{ProviderFactory, ProviderImpl},
        DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::{CalError, KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig},
    provider::linux::{key_handle::LinuxKeyHandle, provider_factory::LinuxProviderFactory},
    storage::{KeyData, StorageManager},
};

#[derive(Clone)]
pub(crate) struct LinuxProvider {
    pub(super) primary_key: tss_esapi::handles::KeyHandle,
    pub(super) context: Arc<Mutex<tss_esapi::Context>>,
    pub(super) impl_config: ProviderImplConfig,
    pub(super) used_factory: LinuxProviderFactory,
    pub(super) storage_manager: Option<StorageManager>,
}

impl ProviderImpl for LinuxProvider {
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        let id = nanoid::nanoid!();

        let key = self
            .context
            .lock()
            .unwrap()
            .create(self.primary_key, spec.try_into()?, None, None, None, None)
            .map_err(|e| {
                CalError::failed_operation("key creation failed", false, Some(anyhow!(e)))
            })?;

        if !spec.ephemeral {
            self.storage_manager
                .as_ref()
                .map(|sm| {
                    let serialized_public = key.out_public.marshall().map_err(|e| {
                        CalError::failed_operation(
                            "failed to serialize public part of key",
                            false,
                            Some(anyhow!(e)),
                        )
                    })?;
                    sm.store(
                        id.clone(),
                        KeyData {
                            id: id.clone(),
                            secret_data: None,
                            public_data: Some(serialized_public),
                            additional_data: Some(key.out_private.value().to_vec()),
                            spec: Spec::KeySpec(spec),
                        },
                    )
                    .map_err(|e| {
                        CalError::failed_operation("failed saving key", true, Some(anyhow!(e)))
                    })
                })
                .transpose()?;
        }

        Ok(KeyHandle {
            implementation: LinuxKeyHandle {
                key_id: id,
                spec,
                storage_manager: self.storage_manager.clone().filter(|_| !spec.ephemeral),
                provider: self.clone(),
                key_data_private: key.out_private,
                key_data_public: key.out_public,
            }
            .into(),
        })
    }

    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        let key_data = self
            .storage_manager
            .as_ref()
            .ok_or_else(|| {
                CalError::failed_operation("Provider has no storage initialised", true, None)
            })
            .and_then(|sm| {
                sm.get(&key_id)
                    .map_err(|e| CalError::missing_key(&key_id, KeyType::Symmetric))
            })?;

        let spec = if let Spec::KeySpec(spec) = key_data.spec {
            spec
        } else {
            return Err(CalError::failed_operation(
                "loaded key has the wrong type",
                true,
                None,
            ));
        };

        let public_data = key_data
            .public_data
            .ok_or_else(|| CalError::missing_value("missing public key definition", true, None))
            .and_then(|data| {
                Public::unmarshall(&data).map_err(|e| {
                    CalError::failed_operation("failed to deserialize key", false, Some(anyhow!(e)))
                })
            })?;

        let private_data = key_data
            .additional_data
            .ok_or_else(|| CalError::missing_value("missing wrapped key data", true, None))
            .and_then(|data| {
                Private::try_from(data).map_err(|e| {
                    CalError::failed_operation("failed to deserialize key", false, Some(anyhow!(e)))
                })
            })?;

        Ok(KeyHandle {
            implementation: LinuxKeyHandle {
                key_id,
                spec,
                storage_manager: self.storage_manager.clone().filter(|_| !spec.ephemeral),
                provider: self.clone(),
                key_data_private: private_data,
                key_data_public: public_data,
            }
            .into(),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn start_ephemeral_dh_exchange(&mut self, spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        Err(CalError::not_implemented())
    }

    fn provider_name(&self) -> String {
        super::NAME.to_owned()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        self.used_factory.get_capabilities(self.impl_config.clone())
    }

    fn get_random(&self, len: usize) -> Vec<u8> {
        self.context
            .lock()
            .unwrap()
            .execute_without_session(|c| c.get_random(len))
            .map(|digest| digest.to_vec())
            .map_err(|e| {
                CalError::failed_operation(
                    "failed to get random data from TPM",
                    false,
                    Some(anyhow!(e)),
                )
            })
            .expect("this should return result")
    }
}

use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    structures::{Digest, Public, PublicBuilder, SymmetricCipherParameters},
};

use crate::{
    common::{
        config::Spec, traits::module_provider::ProviderImpl, DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::{CalError, KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig},
    provider::linux::{key_handle::LinuxKeyHandle, provider_factory::LinuxProviderFactory},
    storage::{KeyData, StorageManager},
};

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
            self.storage_manager.as_ref().map(|sm| {
                sm.store(
                    id.clone(),
                    KeyData {
                        id: id.clone(),
                        secret_data: None,
                        public_data: None,
                        additional_data: Some(key.out_private.value().to_vec()),
                        spec: Spec::KeySpec(spec),
                    },
                )
            });
        }

        Ok(KeyHandle {
            implementation: LinuxKeyHandle {
                key_id: id,
                spec,
                storage_manager: self.storage_manager.clone().filter(|_| !spec.ephemeral),
                context: self.context.clone(),
                key_data: Arc::new(key),
                primary_key: self.primary_key,
            }
            .into(),
        })
    }

    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
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
        self.get_capabilities()
    }
}

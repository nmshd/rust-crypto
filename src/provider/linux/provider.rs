use crate::{
    common::{
        config::Spec, traits::module_provider::ProviderImpl, DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::{CalError, KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig},
    provider::linux::provider_factory::LinuxProviderFactory,
    storage::StorageManager,
};

pub(crate) struct LinuxProvider {
    pub(super) primary_key: tss_esapi::handles::KeyHandle,
    pub(super) context: tss_esapi::Context,
    pub(super) impl_config: ProviderImplConfig,
    pub(super) used_factory: LinuxProviderFactory,
    pub(super) storage_manager: Option<StorageManager>,
}

impl ProviderImpl for LinuxProvider {
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
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

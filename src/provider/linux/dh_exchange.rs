use crate::{
    common::{traits::key_handle::DHKeyExchangeImpl, KeyHandle},
    prelude::{CalError, KeySpec},
    storage::StorageManager,
};

#[derive(Clone, Debug)]
pub(crate) struct LinuxDHExchange {
    pub(crate) key_id: String,
    pub(crate) spec: KeySpec,
    pub(crate) storage_manager: Option<StorageManager>,
}

impl DHKeyExchangeImpl for LinuxDHExchange {
    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id)
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        Err(CalError::not_implemented())
    }
}

use crate::{
    common::traits::key_handle::DHKeyExchangeImpl,
    prelude::{CalError, KeyPairSpec},
    storage::StorageManager,
};

pub(crate) struct AndroidDHExchange {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) storage_manager: Option<StorageManager>,
}

impl DHKeyExchangeImpl for AndroidDHExchange {
    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Get the public key of the internal key pair to use for the other party"]
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    #[doc = " Derive client session keys (rx, tx) - client is the templator in your code"]
    fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        todo!()
    }

    #[doc = " Derive server session keys (rx, tx) - server is the requestor in your code"]
    fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        todo!()
    }

    fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        todo!()
    }

    fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        todo!()
    }
}

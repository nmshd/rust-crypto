use robusta_jni::jni::{
    objects::{AutoLocal, JObject},
    JavaVM,
};
use tracing::trace;

use crate::{
    common::{
        error::ToCalError,
        traits::{key_handle::DHKeyExchangeImpl, module_provider::ProviderImpl},
        KeyHandle,
    },
    prelude::{CalError, KeyPairSpec, KeySpec},
    tpm::android::{
        provider::AndroidProvider,
        utils::get_exchange_algorithm,
        wrapper::{
            self, context, key_agreement::jni::KeyAgreement, key_store::store::jni::KeyStore,
        },
        ANDROID_KEYSTORE,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct AndroidDHExchange {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) provider: AndroidProvider,
}

impl AndroidDHExchange {
    fn derive_key(&mut self, other_key: Vec<u8>) -> Result<Vec<u8>, CalError> {
        trace!(
            "AndroidDHExchange::derive_key called with key id: {}",
            self.key_id
        );
        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let own_key = key_store
            .getKey(&env, self.key_id.to_string(), JObject::null())
            .err_internal()?;

        let key_factory =
            wrapper::key_factory::jni::KeyFactory::getInstance(&env, "EC".to_string())
                .err_internal()?;
        let x509spec =
            wrapper::key_spec::jni::X509EncodedKeySpec::new(&env, other_key).err_internal()?;
        let other_key = key_factory
            .generatePublic(&env, x509spec.raw.as_obj())
            .err_internal()?;
        let other_key = wrapper::key_generation::key::jni::Key { raw: other_key.raw };

        let algorithm: String = get_exchange_algorithm(self.spec);

        let key_agreement =
            KeyAgreement::getInstance(&env, algorithm, ANDROID_KEYSTORE.to_string())
                .err_internal()?;

        key_agreement.init(&env, own_key).err_internal()?;

        key_agreement
            .doPhase(&env, other_key, true)
            .err_internal()?;

        let shared_secret = key_agreement.generateSecret(&env).err_internal()?;
        Ok(shared_secret.to_vec())
    }
}

impl DHKeyExchangeImpl for AndroidDHExchange {
    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Get the public key of the internal key pair to use for the other party"]
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let entry = key_store
            .getEntry(&env, self.key_id.to_string())
            .err_internal()?;

        let entry = wrapper::key_store::key_entry::PrivateKeyEntry {
            raw: AutoLocal::new(&env, Into::<JObject>::into(entry)),
        };

        let public_key = entry
            .get_certificate(&env)
            .err_internal()?
            .getPublicKey(&env)
            .err_internal()?
            .getEncoded(&env)
            .err_internal()?;
        Ok(public_key)
    }

    #[doc = " Derive client session keys (rx, tx) - client is the templator in your code"]
    fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        let shared_secret = self.derive_key(server_pk.to_vec())?;
        // Split the shared secret into rx and tx keys
        let mid = shared_secret.len() / 2;
        Ok((shared_secret[..mid].to_vec(), shared_secret[mid..].to_vec()))
    }

    #[doc = " Derive server session keys (rx, tx) - server is the requestor in your code"]
    fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        let shared_secret = self.derive_key(client_pk.to_vec())?;
        // Split the shared secret into rx and tx keys, on the server side, the upper half comes first
        let mid = shared_secret.len() / 2;
        Ok((shared_secret[mid..].to_vec(), shared_secret[..mid].to_vec()))
    }

    fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        let (rx_key, tx_key) = self.derive_client_session_keys(server_pk)?;

        let spec = KeySpec {
            cipher: self.spec.cipher.ok_or_else(|| {
                CalError::unsupported_algorithm(
                    "Cipher is not set for the key pair spec".to_string(),
                )
            })?,
            signing_hash: self.spec.signing_hash,
            ephemeral: self.spec.ephemeral,
            non_exportable: self.spec.non_exportable,
        };

        let rx_handle = self.provider.import_key(spec, &rx_key)?;
        let tx_handle = self.provider.import_key(spec, &tx_key)?;
        Ok((rx_handle, tx_handle))
    }

    fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        let (rx_key, tx_key) = self.derive_server_session_keys(client_pk)?;

        let spec = KeySpec {
            cipher: self.spec.cipher.ok_or_else(|| {
                CalError::unsupported_algorithm(
                    "Cipher is not set for the key pair spec".to_string(),
                )
            })?,
            signing_hash: self.spec.signing_hash,
            ephemeral: self.spec.ephemeral,
            non_exportable: self.spec.non_exportable,
        };

        let rx_handle = self.provider.import_key(spec, &rx_key)?;
        let tx_handle = self.provider.import_key(spec, &tx_key)?;
        Ok((rx_handle, tx_handle))
    }
}

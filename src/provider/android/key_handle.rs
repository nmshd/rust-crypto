use super::utils::get_cipher_name;
use crate::prelude::Cipher;
use crate::provider::android::utils::{get_cipher_padding, get_mode_name};
use crate::provider::android::wrapper::key_generation::gcm_parameter_spec::jni::GcmParameterSpec;
use crate::provider::software::key_handle::id_from_buffer;
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec},
        error::{CalError, ToCalError},
        traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
        DHExchange, KeyHandle,
    },
    provider::android::{
        utils::{get_asym_cipher_mode, get_signature_algorithm, get_sym_cipher_mode},
        wrapper::{
            self, context,
            key_generation::iv_parameter_spec::jni::IvParameterSpec,
            key_store::{signature::jni::Signature, store::jni::KeyStore},
        },
        ANDROID_KEYSTORE,
    },
    storage::StorageManager,
};
use anyhow::anyhow;
use blake2::Blake2bVar;
use digest::Update;
use digest::VariableOutput;
use robusta_jni::jni::{objects::JObject, JavaVM};
use tracing::trace;

#[derive(Clone, Debug)]
pub(crate) struct AndroidKeyHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeySpec,
    pub(crate) storage_manager: Option<StorageManager>,
}

#[derive(Clone, Debug)]
pub(crate) struct AndroidKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) storage_manager: Option<StorageManager>,
}

impl KeyHandleImpl for AndroidKeyHandle {
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        trace!("encrypting");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let config_mode = get_sym_cipher_mode(self.spec.cipher)?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(&env, config_mode)
            .err_internal()?;

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;

        let iv = if matches!(self.spec.cipher, Cipher::AesGcm128 | Cipher::AesGcm256) {
            if !iv.is_empty() {
                let iv_spec = GcmParameterSpec::new(&env, 128, iv).err_internal()?;
                cipher
                    .init2(&env, 1, key, iv_spec.raw.as_obj())
                    .err_internal()?;
                iv.to_vec()
            } else {
                cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
                let iv = cipher.getIV(&env).err_internal()?;
                let iv_spec = GcmParameterSpec::new(&env, 128, &iv).err_internal()?;
                cipher
                    .init2(&env, 1, key, iv_spec.raw.as_obj())
                    .err_internal()?;
                iv
            }
        } else {
            if !iv.is_empty() {
                let iv_spec = IvParameterSpec::new(&env, &iv).err_internal()?;
                cipher
                    .init2(&env, 1, key, iv_spec.raw.as_obj())
                    .err_internal()?;
                iv.to_vec()
            } else {
                cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
                cipher.getIV(&env).err_internal()?
            }
        };
        let encrypted = cipher.doFinal(&env, data.to_vec()).err_internal()?;

        Ok((encrypted, iv.to_vec()))
    }

    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        trace!("decrypting");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let cipher_mode = get_sym_cipher_mode(self.spec.cipher)?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(&env, cipher_mode)
            .err_internal()?;

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;

        if matches!(self.spec.cipher, Cipher::AesGcm128 | Cipher::AesGcm256) {
            let iv_spec = GcmParameterSpec::new(&env, 128, iv).err_internal()?;
            cipher
                .init2(&env, 2, key, iv_spec.raw.as_obj())
                .err_internal()?;
        } else {
            let iv_spec = IvParameterSpec::new(&env, &iv).err_internal()?;
            cipher
                .init2(&env, 2, key, iv_spec.raw.as_obj())
                .err_internal()?;
        }

        let decrypted = cipher
            .doFinal(&env, encrypted_data.to_vec())
            .err_internal()?;

        Ok(decrypted)
    }

    fn hmac(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn verify_hmac(&self, _data: &[u8], _hmac: &[u8]) -> Result<bool, CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError> {
        trace!("deriving key");
        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        // encrypt nonce with existing key, re-use the same nonce
        let encrypted_nonce = self.encrypt_with_iv(nonce, nonce)?;

        let mut spec = self.spec.clone();
        spec.ephemeral = true;
        let key_length = spec.cipher.len();

        let mut hasher = Blake2bVar::new(key_length).map_err(|e| {
            let cal_err = CalError::bad_parameter(
                "Blake2b failed to initialize".to_owned(),
                false,
                Some(anyhow!(e)),
            );
            tracing::warn!(err = %cal_err, "Failed Blake2b init.");
            cal_err
        })?;

        hasher.update(&encrypted_nonce);

        let mut derived_key = vec![0u8; key_length];

        hasher
            .finalize_variable(derived_key.as_mut_slice())
            .map_err(|e| {
                let cal_err = CalError::bad_parameter(
                    "Blake2b failed to write hash.".to_owned(),
                    false,
                    Some(anyhow!(e)),
                );
                tracing::warn!(err = %cal_err, "Failed Blake2b init.");
                cal_err
            })?;

        let id = id_from_buffer(self.key_id.as_bytes(), nonce);

        let jderived_key = env.byte_array_from_slice(&derived_key).err_internal()?;
        let algorithm = get_cipher_name(spec.cipher)?;
        let jalgorithm = env.new_string(algorithm).err_internal()?;
        let key = env
            .new_object(
                "javax/crypto/spec/SecretKeySpec",
                "([BLjava/lang/String;)V",
                &[jderived_key.into(), jalgorithm.into()],
            )
            .err_internal()?;

        let key_entry =
            wrapper::key_store::key_entry::SecretKeyEntry::new(&env, key).err_internal()?;

        let key_store = wrapper::key_store::store::jni::KeyStore::getInstance(
            &env,
            ANDROID_KEYSTORE.to_owned(),
        )
        .err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let protections =
            wrapper::key_generation::protections_builder::ProtectionsBuilder::new(&env, 3)
                .err_internal()?
                .set_block_modes(&env, vec![get_mode_name(spec.cipher)?])
                .err_internal()?
                .set_encryption_paddings(&env, vec![get_cipher_padding(spec.cipher)?.into()])
                .err_internal()?
                .set_randomized_encryption_required(&env, false)
                .err_internal()?
                .set_is_strongbox_backed(&env, false)
                .err_internal()?
                .build(&env)
                .err_internal()?;

        key_store
            .set_entry(
                &env,
                id.clone(),
                key_entry.raw.as_obj(),
                Some(protections.raw.as_obj()),
            )
            .err_internal()?;

        Ok(KeyHandle {
            implementation: Into::into(AndroidKeyHandle {
                key_id: id,
                spec,
                storage_manager: self.storage_manager.clone(),
            }),
        })
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn delete(mut self) -> Result<(), CalError> {
        if let Err(e) = self.delete_internal() {
            tracing::warn!("Failed to delete key on device: {:?}", e);
        }

        if let Some(storage_manager) = &self.storage_manager {
            storage_manager.delete(self.key_id.clone())?;
        }

        Ok(())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    fn spec(&self) -> KeySpec {
        self.spec
    }
}

impl KeyPairHandleImpl for AndroidKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        trace!("signing");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let private_key = key_store
            .getKey(&env, self.key_id.to_string(), JObject::null())
            .err_internal()?;

        let signature_algorithm = get_signature_algorithm(self.spec)?;

        let s = Signature::getInstance(&env, signature_algorithm).err_internal()?;

        s.initSign(&env, private_key.raw.as_obj()).err_internal()?;

        let data_bytes = data.to_vec().into_boxed_slice();

        s.update(&env, data_bytes).err_internal()?;

        let output = s.sign(&env).err_internal()?;

        Ok(output)
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        trace!("verifying");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let signature_algorithm = get_signature_algorithm(self.spec)?;

        let s = Signature::getInstance(&env, signature_algorithm).err_internal()?;

        let cert = key_store
            .getCertificate(&env, self.key_id.to_string())
            .err_internal()?;

        s.initVerify(&env, cert).err_internal()?;

        let data_bytes = data.to_vec().into_boxed_slice();
        s.update(&env, data_bytes).err_internal()?;

        let signature_boxed = signature.to_vec().into_boxed_slice();
        let output = s.verify(&env, signature_boxed).err_internal()?;

        Ok(output)
    }

    fn encrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        trace!("encrypting");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            get_asym_cipher_mode(self.spec.asym_spec)?,
        )
        .err_internal()?;

        let key = key_store
            .getCertificate(&env, self.key_id.to_owned())
            .err_internal()?
            .getPublicKey(&env)
            .err_internal()?;
        cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
        let encrypted = cipher
            .doFinal(&env, encrypted_data.to_vec())
            .err_internal()?;

        Ok(encrypted)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        trace!("decrypting");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            get_asym_cipher_mode(self.spec.asym_spec)?,
        )
        .err_internal()?;

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;
        cipher.init(&env, 2, key.raw.as_obj()).err_internal()?;

        let decrypted = cipher
            .doFinal(&env, encrypted_data.to_vec())
            .err_internal()?;

        Ok(decrypted)
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        trace!("getting public key");

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let key = key_store
            .getCertificate(&env, self.key_id.to_owned())
            .err_internal()?;

        let public_key = key.getPublicKey(&env).err_internal()?;

        let encoded = public_key.getEncoded(&env).err_internal()?;

        Ok(encoded)
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        Err(CalError::not_implemented())
    }

    fn delete(mut self) -> Result<(), CalError> {
        if let Err(e) = self.delete_internal() {
            tracing::warn!("Failed to delete key on device: {:?}", e);
        }

        if let Some(storage_manager) = &self.storage_manager {
            storage_manager.delete(self.key_id.clone())?;
        }

        Ok(())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    fn spec(&self) -> KeyPairSpec {
        self.spec
    }
}

impl AndroidKeyHandle {
    fn delete_internal(&mut self) -> Result<(), CalError> {
        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let keystore = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        keystore.load(&env, None).err_internal()?;
        keystore
            .deleteEntry(&env, self.key_id.clone())
            .err_internal()?;
        Ok(())
    }
}

impl AndroidKeyPairHandle {
    fn delete_internal(&mut self) -> Result<(), CalError> {
        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let keystore = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        keystore.load(&env, None).err_internal()?;
        keystore
            .deleteEntry(&env, self.key_id.clone())
            .err_internal()?;
        Ok(())
    }
}

/// remove ephemeral key from keystore when the handle is dropped
impl Drop for AndroidKeyHandle {
    fn drop(&mut self) {
        if self.storage_manager.is_none() {
            if let Err(e) = self.delete_internal() {
                tracing::warn!("Failed to delete ephemeral key on device: {:?}", e);
            }
        }
    }
}

impl Drop for AndroidKeyPairHandle {
    fn drop(&mut self) {
        if self.storage_manager.is_none() {
            if let Err(e) = self.delete_internal() {
                tracing::warn!("Failed to delete ephemeral key on device: {:?}", e);
            }
        }
    }
}

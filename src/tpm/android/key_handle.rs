use std::sync::Arc;

use super::utils::get_iv_size;
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec},
        error::{CalError, ToCalError},
        traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
        DHExchange,
    },
    tpm::android::{
        utils::{
            get_asym_cipher_mode, get_signature_algorithm, get_sym_cipher_mode, load_iv, store_iv,
        },
        wrapper::{
            self,
            key_generation::iv_parameter_spec::jni::IvParameterSpec,
            key_store::{signature::jni::Signature, store::jni::KeyStore},
        },
        ANDROID_KEYSTORE,
    },
};

use robusta_jni::jni::{objects::JObject, JavaVM};
use std::sync::Mutex;
use tracing::{debug, info};

pub(crate) struct AndroidKeyHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeySpec,
    pub(crate) java_vm: Arc<Mutex<JavaVM>>,
}

pub(crate) struct AndroidKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) java_vm: Arc<Mutex<JavaVM>>,
}

impl KeyHandleImpl for AndroidKeyHandle {
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        info!("encrypting");

        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let config_mode = get_sym_cipher_mode(self.spec.cipher)?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(&env, config_mode)
            .err_internal()?;

        // symmetric encryption needs an IV

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;
        cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
        let iv = cipher.getIV(&env).err_internal()?;
        let encrypted = cipher.doFinal(&env, data.to_vec()).err_internal()?;
        let encrypted = store_iv(encrypted, iv);

        Ok(encrypted)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

        let cipher_mode = get_sym_cipher_mode(self.spec.cipher)?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(&env, cipher_mode)
            .err_internal()?;

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;

        let (data, iv) = load_iv(encrypted_data, get_iv_size(self.spec.cipher));
        let iv_spec = IvParameterSpec::new(&env, &iv).err_internal()?;
        cipher
            .init2(&env, 2, key, iv_spec.raw.as_obj())
            .err_internal()?;

        let decrypted = cipher.doFinal(&env, data).err_internal()?;

        Ok(decrypted)
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }
}

impl KeyPairHandleImpl for AndroidKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        info!("signing");

        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let private_key = key_store
            .getKey(&env, self.key_id.to_string(), JObject::null())
            .err_internal()?;

        let signature_algorithm = get_signature_algorithm(self.spec)?;
        debug!("Signature Algorithm: {}", signature_algorithm);

        let s = Signature::getInstance(&env, signature_algorithm).err_internal()?;

        s.initSign(&env, private_key.raw.as_obj()).err_internal()?;

        let data_bytes = data.to_vec().into_boxed_slice();

        s.update(&env, data_bytes).err_internal()?;

        let output = s.sign(&env).err_internal()?;

        Ok(output)
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        info!("verifiying");

        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let signature_algorithm = get_signature_algorithm(self.spec)?;
        debug!("Signature Algorithm: {}", signature_algorithm);

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

    fn encrypt_data(&self, encryped_data: &[u8]) -> Result<Vec<u8>, CalError> {
        info!("encrypting");

        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

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
            .doFinal(&env, encryped_data.to_vec())
            .err_internal()?;

        Ok(encrypted)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        info!("decrypting");

        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

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
        info!("getting public key");

        let vm = self.java_vm.lock().expect("Can't lock mutex");
        let attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let key = key_store
            .getCertificate(&env, self.key_id.to_owned())
            .err_internal()?;

        let _public_key = key.getPublicKey(&env).err_internal()?;

        todo!("turn public key into bytes");
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        todo!()
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        todo!()
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }
}

use std::sync::Arc;

use super::{provider::AndroidProvider, utils::get_iv_size};
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec},
        crypto::KeyUsage,
        error::SecurityModuleError,
        traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
        DHExchange,
    },
    tpm::{
        android::{
            utils::{get_asym_cipher_mode, get_signature_algorithm, load_iv, store_iv},
            wrapper::{
                self,
                key_generation::iv_parameter_spec::jni::IvParameterSpec,
                key_store::{signature::jni::Signature, store::jni::KeyStore},
            },
            ANDROID_KEYSTORE,
        },
        core::error::{ToTpmError, TpmError},
    },
};

use robusta_jni::jni::{objects::JObject, JavaVM};
use std::sync::Mutex;
use tracing::{debug, info, instrument};

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
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("encrypting");

        let vm = self.java_vm.lock().unwrap();
        let env = vm.get_env().unwrap();
        let thread = vm.attach_current_thread().unwrap();

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let config_mode: Result<String, SecurityModuleError> = self.spec.cipher.into();

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            config_mode.as_ref().unwrap().to_string(),
        )
        .err_internal()?;

        // symetric encryption needs an IV

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;
        cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
        let iv = cipher.getIV(&env).err_internal()?;
        let encrypted = cipher.doFinal(&env, data.to_vec()).err_internal()?;
        let encrypted = store_iv(encrypted, iv);

        Ok(encrypted)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        let vm = self.java_vm.lock().unwrap();
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

        let cipher_mode: Result<String, SecurityModuleError> = self.spec.cipher.into();

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            cipher_mode.as_ref().unwrap().to_string(),
        )
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

    fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    fn id(&self) -> Result<String, SecurityModuleError> {
        Ok(self.key_id.clone())
    }
}

impl KeyPairHandleImpl for AndroidKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("signing");

        let vm = self.java_vm.lock().unwrap();
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

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

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        info!("verifiying");

        let vm = self.java_vm.lock().unwrap();
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

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

    fn encrypt_data(&self, encryped_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("encrypting");

        let vm = self.java_vm.lock().unwrap();
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

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

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("decrypting");

        let vm = self.java_vm.lock().unwrap();
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

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

    fn get_public_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        info!("getting public key");

        let vm = self.java_vm.lock().unwrap();
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let key = key_store
            .getCertificate(&env, self.key_id.to_owned())
            .err_internal()?;

        let public_key = key.getPublicKey(&env).err_internal()?;

        todo!("turn public key into bytes");
    }

    fn extract_key(&self) -> Result<Vec<u8>, SecurityModuleError> {
        todo!()
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, SecurityModuleError> {
        todo!()
    }

    fn id(&self) -> Result<String, SecurityModuleError> {
        Ok(self.key_id.clone())
    }
}

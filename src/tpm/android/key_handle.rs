use super::provider::AndroidProvider;
use crate::{
    common::{
        crypto::KeyUsage,
        error::SecurityModuleError,
        traits::{key_handle::KeyHandle, module_provider_config::ProviderConfig},
    },
    tpm::{
        android::{
            config::{self, AndroidConfig},
            utils::{load_iv, store_iv},
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
use async_trait::async_trait;
use robusta_jni::jni::objects::JObject;
use tracing::{debug, info, instrument};

/// Implementation of the `KeyHandle` trait for the `AndroidProvider` struct.
/// All of the functions in this KeyHandle are basically re-implementations
/// of the equivalent Java functions in the Android KeyStore API.
#[async_trait]
impl KeyHandle for AndroidProvider {
    /// Signs the given data using the Android KeyStore.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte array of data to be signed.
    ///
    /// # Java Example
    ///
    /// ```java
    /// KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
    /// ks.load(null);
    /// KeyStore.Entry entry = ks.getEntry(alias, null);
    /// if (!(entry instanceof PrivateKeyEntry)) {
    ///     Log.w(TAG, "Not an instance of a PrivateKeyEntry");
    ///     return null;
    /// }
    /// Signature s = Signature.getInstance("SHA256withECDSA");
    /// s.initSign(((PrivateKeyEntry) entry).getPrivateKey());
    /// s.update(data);
    /// byte[] signature = s.sign();
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the signed data as a `Vec<u8>` if successful, or a `SecurityModuleError` if an error occurs.
    #[instrument(skip(data))]
    async fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        // check that signing is allowed
        let config = self
            .config
            .as_ref()
            .unwrap()
            .as_any()
            .await
            .downcast_ref::<AndroidConfig>()
            .unwrap();

        if !config.key_usages.contains(&KeyUsage::SignEncrypt) {
            return Err(TpmError::UnsupportedOperation(
                "KeyUsage::SignEncrypt was not provided".to_owned(),
            )
            .into());
        }

        let vm = config.vm.as_ref().unwrap().lock().await;
        let env = vm.get_env().unwrap();

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let private_key = key_store
            .getKey(&env, self.key_id().to_string(), JObject::null())
            .err_internal()?;

        let signature_algorithm: Result<String, SecurityModuleError> = config.mode.into();
        debug!(
            "Signature Algorithm: {}",
            signature_algorithm.as_ref().unwrap()
        );

        let s = Signature::getInstance(&env, signature_algorithm.unwrap().to_string())
            .err_internal()?;

        s.initSign(&env, private_key.raw.as_obj()).err_internal()?;

        let data_bytes = data.to_vec().into_boxed_slice();

        s.update(&env, data_bytes).err_internal()?;

        let output = s.sign(&env).err_internal()?;

        Ok(output)
    }

    /// Decrypts the given encrypted data using the Android KeyStore.
    ///
    /// # Arguments
    ///
    /// * `encrypted_data` - The encrypted data to be decrypted.
    ///
    /// # Java Example
    ///
    /// ```java
    /// KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    /// keyStore.load(null);
    /// PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYNAME, null);
    /// PublicKey publicKey = keyStore.getCertificate(KEYNAME).getPublicKey();
    /// Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    /// cipher.init(Cipher.DECRYPT_MODE, privateKey);
    /// byte[] decrypted = cipher.doFinal(encrypted);
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the decrypted data as a `Vec<u8>` if successful, or a `SecurityModuleError` if an error occurs.
    #[instrument(skip(encrypted_data))]
    async fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("decrypting data");

        let config = self
            .config
            .as_ref()
            .unwrap()
            .as_any()
            .await
            .downcast_ref::<AndroidConfig>()
            .unwrap();

        let vm = config.vm.as_ref().unwrap().lock().await;
        let env = vm.get_env().unwrap();

        let cipher_mode: Result<String, SecurityModuleError> = config.mode.into();

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            cipher_mode.as_ref().unwrap().to_string(),
        )
        .err_internal()?;

        let decrypted = match config.mode {
            config::EncryptionMode::Sym(cipher_mode) => {
                let key = key_store
                    .getKey(&env, self.key_id().to_owned(), JObject::null())
                    .err_internal()?;

                let (data, iv) = load_iv(encrypted_data, cipher_mode.into());
                let iv_spec = IvParameterSpec::new(&env, &iv).err_internal()?;
                cipher
                    .init2(&env, 2, key, iv_spec.raw.as_obj())
                    .err_internal()?;

                cipher.doFinal(&env, data).err_internal()?
            }
            config::EncryptionMode::ASym { algo: _, digest: _ } => {
                let key = key_store
                    .getKey(&env, self.key_id.to_owned(), JObject::null())
                    .err_internal()?;
                cipher.init(&env, 2, key.raw.as_obj()).err_internal()?;

                cipher
                    .doFinal(&env, encrypted_data.to_vec())
                    .err_internal()?
            }
        };

        Ok(decrypted)
    }

    /// Encrypts the given data using the Android KeyStore.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to be encrypted.
    ///
    /// # Java Example
    ///
    /// ```java
    /// KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    /// keyStore.load(null);
    /// PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYNAME, null);
    /// PublicKey publicKey = keyStore.getCertificate(KEYNAME).getPublicKey();
    /// Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    /// byte[] encrypted;
    /// cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    /// encrypted = cipher.doFinal(text.getBytes());
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the encrypted data as a `Vec<u8>` if successful, or a `SecurityModuleError` if an error occurs.
    #[instrument(skip(data))]
    async fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("encrypting");

        let config = self
            .config
            .as_ref()
            .unwrap()
            .as_any()
            .await
            .downcast_ref::<AndroidConfig>()
            .unwrap();

        let vm = config.vm.as_ref().unwrap().lock().await;
        let env = vm.get_env().unwrap();

        info!("before getInstance");

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        info!("after getInstance");
        key_store.load(&env, None).err_internal()?;
        info!("after load");

        let config_mode: Result<String, SecurityModuleError> = config.mode.into();

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            config_mode.as_ref().unwrap().to_string(),
        )
        .err_internal()?;

        // symetric encryption needs an IV
        let encrypted = match config.mode {
            config::EncryptionMode::Sym(_) => {
                let key = key_store
                    .getKey(&env, self.key_id().to_owned(), JObject::null())
                    .err_internal()?;
                cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
                let iv = cipher.getIV(&env).err_internal()?;
                let encrypted = cipher.doFinal(&env, data.to_vec()).err_internal()?;
                store_iv(encrypted, iv)
            }
            config::EncryptionMode::ASym { algo: _, digest: _ } => {
                let key = key_store
                    .getCertificate(&env, self.key_id().to_owned())
                    .err_internal()?
                    .getPublicKey(&env)
                    .err_internal()?;
                cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
                cipher.doFinal(&env, data.to_vec()).err_internal()?
            }
        };

        Ok(encrypted)
    }

    /// Verifies the signature of the given data using the Android KeyStore.
    ///
    /// # Arguments
    ///
    /// * `data` - The data whose signature needs to be verified.
    /// * `signature` - The signature to be verified.
    ///
    /// # Java Example
    ///
    /// ```java
    /// KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
    /// ks.load(null);
    /// KeyStore.Entry entry = ks.getEntry(alias, null);
    /// if (!(entry instanceof PrivateKeyEntry)) {
    ///     Log.w(TAG, "Not an instance of a PrivateKeyEntry");
    ///     return false;
    /// }
    /// Signature s = Signature.getInstance("SHA256withECDSA");
    /// s.initVerify(((PrivateKeyEntry) entry).getCertificate());
    /// s.update(data);
    /// boolean valid = s.verify(signature);
    /// ```
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing `true` if the signature is valid, `false` otherwise, or a `SecurityModuleError` if an error occurs.
    #[instrument(skip(data, signature))]
    async fn verify_signature(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, SecurityModuleError> {
        info!("verifiying");

        let config = self
            .config
            .as_ref()
            .unwrap()
            .as_any()
            .await
            .downcast_ref::<AndroidConfig>()
            .unwrap();

        let vm = config.vm.as_ref().unwrap().lock().await;
        let env = vm.get_env().unwrap();

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let signature_algorithm: Result<String, SecurityModuleError> = config.mode.into();
        let signature_algorithm = signature_algorithm.unwrap();
        debug!("Signature Algorithm: {}", signature_algorithm);

        let s = Signature::getInstance(&env, signature_algorithm.to_string()).err_internal()?;

        let cert = key_store
            .getCertificate(&env, self.key_id().to_string())
            .err_internal()?;

        s.initVerify(&env, cert).err_internal()?;

        let data_bytes = data.to_vec().into_boxed_slice();
        s.update(&env, data_bytes).err_internal()?;

        let signature_boxed = signature.to_vec().into_boxed_slice();
        let output = s.verify(&env, signature_boxed).err_internal()?;

        Ok(output)
    }
}

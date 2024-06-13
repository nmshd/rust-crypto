pub mod android_logger;
pub mod config;
pub(crate) mod error;
pub mod knox;
pub(crate) mod utils;
pub(crate) mod wrapper;

use std::any::Any;

use robusta_jni::jni::objects::JObject;
use tracing::{debug, info, instrument};
use utils::{
    get_algorithm, get_cipher_mode, get_digest, get_iv_len, get_key_size, get_padding,
    get_signature_algorithm, get_signature_padding, get_sym_block_mode, load_iv, store_iv,
};
use wrapper::key_generation::iv_parameter_spec::jni::IvParameterSpec;

use crate::common::crypto::KeyUsage;
use crate::common::error::SecurityModuleError;
use crate::common::traits::key_handle::KeyHandle;
use crate::common::{
    crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers},
    traits::module_provider::Provider,
};
use crate::tpm::android::config::AndroidConfig;
use crate::tpm::android::wrapper::key_store::key_store::jni::KeyStore;
use crate::tpm::android::wrapper::key_store::signature::jni::Signature;
use crate::tpm::core::error::ToTpmError;
use crate::tpm::core::error::TpmError;

const ANDROID_KEYSTORE: &str = "AndroidKeyStore";

/// A TPM-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations in an Android environment.
///
/// This provider uses the Android Keystore API to interact
/// with the Trusted Execution Environment (TEE), or the devices Secure Element(Like the Titan M chip in a Google Pixel)
/// for operations like signing, encryption, and decryption.
/// It provides a secure and hardware-backed solution for managing cryptographic keys and performing
/// cryptographic operations on Android.
#[derive(Debug)]
pub(crate) struct AndroidProvider {
    key_id: String,
    config: Option<AndroidConfig>,
}

impl AndroidProvider {
    /// Constructs a new `AndroidProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    /// * `config` - Configuration
    ///
    /// # Returns
    ///
    /// A new instance of `AndroidProvider` with the specified `key_id`.
    #[instrument]
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            config: None,
        }
    }

    fn apply_config(&mut self, config: AndroidConfig) -> Result<(), SecurityModuleError> {
        // TODO: verify config
        self.config = Some(config);
        Ok(())
    }
}

/// Implementation of the `Provider` trait for the Android platform.
///
/// This struct provides methods for key generation, key loading, and module initialization
/// specific to Android.
impl Provider for AndroidProvider {
    /// Generates a key with the parameters specified when the module was initialized.
    ///
    /// The key is generated using the Android Keystore API and is stored securely in the device's
    /// Trusted Execution Environment (TEE) or Secure Element. It first attempts to generate a key
    /// withing the devices StrongBox (Secure Element), and if that fails, because it is not available,
    /// it falls back to the TEE. We have to do this because the KeyStore does not automatically select
    /// the highest security level available.
    ///
    /// # Java Example
    ///
    /// ```java
    /// KeyPairGenerator kpg = KeyPairGenerator.getInstance(
    ///         KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
    /// kpg.initialize(new KeyGenParameterSpec.Builder(
    ///         alias,
    ///         KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
    ///         .setDigests(KeyProperties.DIGEST_SHA256,
    ///             KeyProperties.DIGEST_SHA512)
    ///         .build());
    /// KeyPair kp = kpg.generateKeyPair();
    /// ```
    ///
    /// # Arguments
    ///
    /// * `key_id` - The identifier for the key.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the key generation is successful, otherwise returns an error of type `SecurityModuleError`.
    #[instrument]
    fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn Any>,
    ) -> Result<(), SecurityModuleError> {
        info!("generating key! {}", key_id);

        // load config
        let config = *config
            .downcast::<AndroidConfig>()
            .map_err(|_| SecurityModuleError::InitializationError("Wrong Config".to_owned()))?;

        let env = config
            .vm
            .as_ref()
            .expect("cannot happen, already checked")
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        // build up key specs
        let mut kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 1 | 2 | 4 | 8)
                .err_internal()?;

        match config.mode {
            config::EncryptionMode::Sym(cipher) => {
                match cipher {
                    BlockCiphers::Aes(mode, size) => {
                        kps_builder = kps_builder
                            .set_block_modes(&env, vec![get_sym_block_mode(mode)?])
                            .err_internal()?
                            .set_encryption_paddings(&env, vec![get_padding(config.mode)?])
                            .err_internal()?
                            .set_key_size(&env, Into::<u32>::into(size) as i32)
                            .err_internal()?;
                    }
                    BlockCiphers::Des => {
                        kps_builder = kps_builder
                            .set_block_modes(&env, vec!["CBC".to_owned()])
                            .err_internal()?
                            .set_encryption_paddings(&env, vec![get_padding(config.mode)?])
                            .err_internal()?;
                    }
                    BlockCiphers::TripleDes(_)
                    | BlockCiphers::Rc2(_)
                    | BlockCiphers::Camellia(_, _) => {
                        Err(TpmError::UnsupportedOperation("not supported".to_owned()))?
                    }
                };
                kps_builder = kps_builder
                    .set_is_strongbox_backed(&env, config.hardware_backed)
                    .err_internal()?;

                let kps = kps_builder.build(&env).err_internal()?;

                let kg = wrapper::key_generation::key_generator::jni::KeyGenerator::getInstance(
                    &env,
                    get_algorithm(config.mode)?,
                    ANDROID_KEYSTORE.to_owned(),
                )
                .err_internal()?;
                kg.init(&env, kps.raw.as_obj()).err_internal()?;

                kg.generateKey(&env).err_internal()?;
            }
            config::EncryptionMode::ASym { algo, digest } => {
                match algo {
                    AsymmetricEncryption::Rsa(_key_bits) => {
                        kps_builder = kps_builder
                            .set_digests(&env, vec![get_digest(digest)?])
                            .err_internal()?
                            .set_signature_paddings(&env, vec![get_signature_padding()?])
                            .err_internal()?
                            .set_encryption_paddings(&env, vec![get_padding(config.mode)?])
                            .err_internal()?
                            .set_key_size(&env, get_key_size(algo)? as i32)
                            .err_internal()?;
                    }
                    AsymmetricEncryption::Ecc(_scheme) => {
                        kps_builder = kps_builder
                            .set_digests(&env, vec![get_digest(digest)?])
                            .err_internal()?;
                    }
                };
                kps_builder = kps_builder
                    .set_is_strongbox_backed(&env, config.hardware_backed)
                    .err_internal()?;

                let kps = kps_builder.build(&env).err_internal()?;

                let kpg = wrapper::key_generation::key_pair_generator::jni::KeyPairGenerator::getInstance(
                    &env,
                    get_algorithm(config.mode)?,
                    ANDROID_KEYSTORE.to_owned(),
                    )
                    .err_internal()?;

                kpg.initialize(&env, kps.raw.as_obj()).err_internal()?;

                kpg.generateKeyPair(&env).err_internal()?;
            }
        }

        debug!("key generated");
        self.apply_config(config)?;

        Ok(())
    }

    /// Loads a key with the specified `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - The identifier for the key.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the key loading is successful, otherwise returns an error of type `SecurityModuleError`.
    #[instrument]
    fn load_key(&mut self, key_id: &str, config: Box<dyn Any>) -> Result<(), SecurityModuleError> {
        key_id.clone_into(&mut self.key_id);

        // load config
        let config = *config
            .downcast::<AndroidConfig>()
            .map_err(|_| SecurityModuleError::InitializationError("Wrong Config".to_owned()))?;
        self.apply_config(config)?;

        Ok(())
    }

    /// Initializes the module with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used.
    /// * `sym_algorithm` - The block cipher algorithm to be used (optional).
    /// * `hash` - The hash algorithm to be used (optional).
    /// * `key_usages` - The list of key usages.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the module initialization is successful, otherwise returns an error of type `SecurityModuleError`.
    #[instrument]
    fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        Ok(())
    }
}

/// Implementation of the `KeyHandle` trait for the `AndroidProvider` struct.
/// All of the functions in this KeyHandle are basically re-implementations
/// of the equivalent Java functions in the Android KeyStore API.
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
    #[instrument]
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        // check that signing is allowed
        let config = self
            .config
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?;

        if !config.key_usages.contains(&KeyUsage::SignEncrypt) {
            return Err(TpmError::UnsupportedOperation(
                "KeyUsage::SignEncrypt was not provided".to_owned(),
            )
            .into());
        }

        let env = config
            .vm
            .as_ref()
            .ok_or_else(|| TpmError::InitializationError("Module is not initialized".to_owned()))?
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let private_key = key_store
            .getKey(&env, self.key_id.clone(), JObject::null())
            .err_internal()?;

        let signature_algorithm = get_signature_algorithm(config.mode)?;
        debug!("Signature Algorithm: {}", signature_algorithm);

        let s = Signature::getInstance(&env, signature_algorithm.to_string()).err_internal()?;

        s.initSign(&env, private_key.raw.as_obj()).err_internal()?;

        let data_bytes = data.to_vec().into_boxed_slice();

        s.update(&env, data_bytes).err_internal()?;
        debug!("Signature Init: {}", s.toString(&env).unwrap());

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
    #[instrument]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("decrypting data");

        let config = self
            .config
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?;

        let env = config
            .vm
            .as_ref()
            .ok_or_else(|| TpmError::InitializationError("Module is not initialized".to_owned()))?
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        let cipher_mode = get_cipher_mode(config.mode)?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(&env, cipher_mode)
            .err_internal()?;

        let decrypted = match config.mode {
            config::EncryptionMode::Sym(cipher_mode) => {
                let key = key_store
                    .getKey(&env, self.key_id.to_owned(), JObject::null())
                    .err_internal()?;

                let (data, iv) = load_iv(encrypted_data, get_iv_len(cipher_mode)?);
                let iv_spec = IvParameterSpec::new(&env, &iv).err_internal()?;
                cipher
                    .init2(&env, 2, key, iv_spec.raw.as_obj())
                    .err_internal()?;

                cipher.doFinal(&env, data).err_internal()?
            }
            config::EncryptionMode::ASym { algo: _, digest: _ } => {
                let key = key_store
                    .getCertificate(&env, self.key_id.to_owned())
                    .err_internal()?
                    .getPublicKey(&env)
                    .err_internal()?;
                cipher.init(&env, 2, key.raw.as_obj()).err_internal()?;

                cipher
                    .doFinal(&env, encrypted_data.to_vec())
                    .err_internal()?
            }
        };

        debug!("decrypted data: {:?}", decrypted);
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
    #[instrument]
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, SecurityModuleError> {
        info!("encrypting");

        let config = self
            .config
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?;

        let env = config
            .vm
            .as_ref()
            .ok_or_else(|| TpmError::InitializationError("Module is not initialized".to_owned()))?
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        info!("before getInstance");

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        info!("after getInstance");
        key_store.load(&env, None).err_internal()?;
        info!("after load");

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            get_cipher_mode(config.mode)?,
        )
        .err_internal()?;

        // symetric encryption needs an IV
        let encrypted = match config.mode {
            config::EncryptionMode::Sym(_) => {
                let key = key_store
                    .getKey(&env, self.key_id.to_owned(), JObject::null())
                    .err_internal()?;
                cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
                let iv = cipher.getIV(&env).err_internal()?;
                let encrypted = cipher.doFinal(&env, data.to_vec()).err_internal()?;
                store_iv(encrypted, iv)
            }
            config::EncryptionMode::ASym { algo: _, digest: _ } => {
                let key = key_store
                    .getCertificate(&env, self.key_id.to_owned())
                    .err_internal()?
                    .getPublicKey(&env)
                    .err_internal()?;
                cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;
                cipher.doFinal(&env, data.to_vec()).err_internal()?
            }
        };

        debug!("encrypted: {:?}", encrypted);
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
    #[instrument]
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
        info!("verifiying");

        let config = self
            .config
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?;

        let env = config
            .vm
            .as_ref()
            .ok_or_else(|| TpmError::InitializationError("Module is not initialized".to_owned()))?
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_string()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let signature_algorithm = get_signature_algorithm(config.mode)?;
        debug!("Signature Algorithm: {}", signature_algorithm);

        let s = Signature::getInstance(&env, signature_algorithm.to_string()).err_internal()?;

        let cert = key_store
            .getCertificate(&env, self.key_id.clone())
            .err_internal()?;

        s.initVerify(&env, cert).err_internal()?;
        debug!("Signature Init: {}", s.toString(&env).unwrap());

        let data_bytes = data.to_vec().into_boxed_slice();
        s.update(&env, data_bytes).err_internal()?;

        let signature_boxed = signature.to_vec().into_boxed_slice();
        let output = s.verify(&env, signature_boxed).err_internal()?;
        debug!("Signature verified: {:?}", output);

        Ok(output)
    }
}

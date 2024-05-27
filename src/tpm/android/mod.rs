pub(crate) mod error;
pub mod knox;
pub(crate) mod utils;
pub(crate) mod wrapper;

use robusta_jni::jni::objects::JObject;
use robusta_jni::jni::JavaVM;
use tracing::{debug, info, instrument};

use crate::common::crypto::algorithms::hashes::Hash;
use crate::common::crypto::KeyUsage;
use crate::common::error::SecurityModuleError;
use crate::common::traits::key_handle::KeyHandle;
use crate::common::{
    crypto::algorithms::encryption::{AsymmetricEncryption, BlockCiphers},
    traits::module_provider::Provider,
};
use crate::tpm::android::wrapper::key_store::key_store::jni::KeyStore;
use crate::tpm::android::wrapper::key_store::signature::jni::Signature;
use crate::tpm::core::error::ToTpmError;
use crate::tpm::core::error::TpmError;

use self::wrapper::get_java_vm;

const ANDROID_KEYSTORE: &str = "AndroidKeyStore";

/// A TPM-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations in an Android environment.
///
/// This provider uses the Android Keystore API to interact
/// with the Trusted Execution Environment (TEE), or the devices Secure Element(Like the Titan M chip in a Google Pixel)
/// for operations like signing, encryption, and decryption.
/// It provides a secure and hardware-backed solution for managing cryptographic keys and performing
/// cryptographic operations on Android.
pub(crate) struct AndroidProvider {
    key_id: String,
    key_algo: Option<AsymmetricEncryption>,
    sym_algo: Option<BlockCiphers>,
    hash: Option<Hash>,
    key_usages: Option<Vec<KeyUsage>>,
    vm: Option<JavaVM>,
}

impl AndroidProvider {
    /// Constructs a new `AndroidProvider`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string identifier for the cryptographic key to be managed by this provider.
    ///
    /// # Returns
    ///
    /// A new instance of `AndroidProvider` with the specified `key_id`.
    #[instrument]
    pub fn new(key_id: String) -> Self {
        Self {
            key_id,
            key_algo: None,
            sym_algo: None,
            hash: None,
            key_usages: None,
            vm: None,
        }
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
    fn create_key(&mut self, key_id: &str) -> Result<(), SecurityModuleError> {
        info!("generating key! {}", key_id);

        // errors if not initialized
        let algorithm = self.get_algorithm()?;
        let digest = self.get_digest()?;

        let env = self
            .vm
            .as_ref()
            .expect("cannot happen, already checked")
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        let strongbox_backed = true;

        let kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 1 | 2 | 4 | 8)
                .err_internal()?
                .set_digests(&env, vec![digest])
                .err_internal()?
                .set_encryption_paddings(&env, vec!["PKCS1Padding".to_owned()])
                .err_internal()?
                .set_signature_paddings(&env, vec!["PKCS1".to_owned()])
                .err_internal()?
                .set_is_strongbox_backed(&env, strongbox_backed)
                .err_internal()?;

        // TODO: if we have a key size, set it
        self.get_key_size();

        let kps = kps_builder.build(&env).err_internal()?;

        let kpg = wrapper::key_generation::key_pair_generator::jni::KeyPairGenerator::getInstance(
            &env,
            algorithm.to_owned(),
            ANDROID_KEYSTORE.to_owned(),
        )
        .err_internal()?;

        kpg.initialize(&env, kps.raw.as_obj()).err_internal()?;

        kpg.generateKeyPair(&env).err_internal()?;

        debug!("key generated");

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
    fn load_key(&mut self, key_id: &str) -> Result<(), SecurityModuleError> {
        self.key_id = key_id.to_owned();
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
    fn initialize_module(
        &mut self,
        key_algorithm: AsymmetricEncryption,
        sym_algorithm: Option<BlockCiphers>,
        hash: Option<Hash>,
        key_usages: Vec<KeyUsage>,
    ) -> Result<(), SecurityModuleError> {
        self.key_algo = Some(key_algorithm);
        self.sym_algo = sym_algorithm;
        self.hash = hash;
        self.key_usages = Some(key_usages);
        self.vm = Some(get_java_vm()?);
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
        if !self
            .key_usages
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?
            .contains(&KeyUsage::SignEncrypt)
        {
            return Err(TpmError::UnsupportedOperation(
                "KeyUsage::SignEncrypt was not provided".to_owned(),
            )
            .into());
        }

        let env = self
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

        let signature_algorithm = match self.key_algo {
            Some(AsymmetricEncryption::Rsa(_)) => "SHA256withRSA",
            Some(AsymmetricEncryption::Ecc(_)) => "SHA256withECDSA",
            _ => panic!("Invalid key_algo"),
        };
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
        let env = self
            .vm
            .as_ref()
            .ok_or_else(|| TpmError::InitializationError("Module is not initialized".to_owned()))?
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        let algorithm = match self.key_algo.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => "RSA",
            AsymmetricEncryption::Ecc(_) => {
                return Err(TpmError::UnsupportedOperation(
                    "EC is not allowed for en/decryption on android".to_owned(),
                )
                .into());
            }
        };

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let key = key_store
            .getKey(&env, self.key_id.to_owned(), JObject::null())
            .err_internal()?;

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            format!("{algorithm}/ECB/PKCS1Padding"),
        )
        .err_internal()?;
        cipher.init(&env, 2, key.raw.as_obj()).err_internal()?;

        let decrypted = cipher
            .doFinal(&env, encrypted_data.to_vec())
            .err_internal()?;

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
        let env = self
            .vm
            .as_ref()
            .ok_or_else(|| TpmError::InitializationError("Module is not initialized".to_owned()))?
            .get_env()
            .map_err(|_| {
                TpmError::InitializationError(
                    "Could not get java environment, this should never happen".to_owned(),
                )
            })?;

        let algorithm = match self.key_algo.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => "RSA",
            AsymmetricEncryption::Ecc(_) => {
                return Err(TpmError::UnsupportedOperation(
                    "EC is not allowed for en/decryption on android".to_owned(),
                )
                .into());
            }
        };

        let key_store = KeyStore::getInstance(&env, ANDROID_KEYSTORE.to_owned()).err_internal()?;
        key_store.load(&env, None).err_internal()?;

        let key = key_store
            .getCertificate(&env, self.key_id.to_owned())
            .err_internal()?
            .getPublicKey(&env)
            .err_internal()?;

        let public_alg = key.getAlgorithm(&env).unwrap();
        debug!("Public Alg: {}", public_alg);

        let cipher = wrapper::key_store::cipher::jni::Cipher::getInstance(
            &env,
            format!("{algorithm}/ECB/PKCS1Padding"),
        )
        .err_internal()?;

        cipher.init(&env, 1, key.raw.as_obj()).err_internal()?;

        let encrypted = cipher.doFinal(&env, data.to_vec()).err_internal()?;

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
        let env = self
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

        let signature_algorithm = match self.key_algo {
            Some(AsymmetricEncryption::Rsa(_)) => "SHA256withRSA",
            Some(AsymmetricEncryption::Ecc(_)) => "SHA256withECDSA",
            _ => panic!("Invalid key_algo"),
        };
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

impl std::fmt::Debug for AndroidProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AndroidProvider")
            .field("key_id", &self.key_id)
            .field("key_algo", &self.key_algo)
            .field("sym_algo", &self.sym_algo)
            .field("hash", &self.hash)
            .field("key_usages", &self.key_usages)
            .finish()
    }
}

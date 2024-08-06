use crate::{
    common::{
        crypto::{
            algorithms::encryption::{AsymmetricEncryption, BlockCiphers},
            KeyUsage,
        },
        error::SecurityModuleError,
        traits::{key_handle::KeyHandle, module_provider::Provider},
    },
    tpm::{
        android::{
            config::AndroidConfig,
            wrapper::key_store::{signature::jni::Signature, store::jni::KeyStore},
        },
        core::error::{ToTpmError, TpmError},
    },
};
use robusta_jni::jni::objects::JObject;
use std::any::Any;
use tracing::{debug, info, instrument};
use utils::{load_iv, store_iv, Padding};
use wrapper::key_generation::iv_parameter_spec::jni::IvParameterSpec;

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

        let config_mode: Result<String, SecurityModuleError> = config.mode.into();

        match config.mode {
            config::EncryptionMode::Sym(cipher) => {
                match cipher {
                    BlockCiphers::Aes(mode, size) => {
                        let mode: Result<String, SecurityModuleError> = mode.try_into();
                        kps_builder = kps_builder
                            .set_block_modes(&env, vec![mode.unwrap()])
                            .err_internal()?
                            .set_encryption_paddings(
                                &env,
                                vec![config_mode.as_ref().unwrap().to_string()],
                            )
                            .err_internal()?
                            .set_key_size(&env, Into::<u32>::into(size) as i32)
                            .err_internal()?;
                    }
                    BlockCiphers::Des => {
                        kps_builder = kps_builder
                            .set_block_modes(&env, vec!["CBC".to_owned()])
                            .err_internal()?
                            .set_encryption_paddings(
                                &env,
                                vec![config_mode.as_ref().unwrap().to_string()],
                            )
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
                    config_mode.as_ref().unwrap().to_string(),
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
                            .set_digests(&env, vec![digest.into()])
                            .err_internal()?
                            .set_signature_paddings(&env, vec![Padding::PKCS1.into()])
                            .err_internal()?
                            .set_encryption_paddings(
                                &env,
                                vec![config_mode.as_ref().unwrap().to_string()],
                            )
                            .err_internal()?
                            .set_key_size(&env, algo.rsa_key_bits().unwrap().into())
                            .err_internal()?;
                    }
                    AsymmetricEncryption::Ecc(_scheme) => {
                        kps_builder = kps_builder
                            .set_digests(&env, vec![digest.into()])
                            .err_internal()?;
                    }
                };
                kps_builder = kps_builder
                    .set_is_strongbox_backed(&env, config.hardware_backed)
                    .err_internal()?;

                let kps = kps_builder.build(&env).err_internal()?;

                let kpg = wrapper::key_generation::key_pair_generator::jni::KeyPairGenerator::getInstance(
                    &env,
                    config_mode.as_ref().unwrap().to_string(),
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

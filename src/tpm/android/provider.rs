use std::{collections::HashSet, fmt::Debug, sync::Arc};

use crate::tpm::android::android_logger::setup_logging;
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher, SymmetricMode},
            KeyBits,
        },
        error::SecurityModuleError,
        traits::module_provider::{ProviderFactory, ProviderImpl},
        DHExchange, KeyHandle, KeyPairHandle,
    },
    tpm::{
        android::{
            key_handle::{AndroidKeyHandle, AndroidKeyPairHandle},
            utils::{get_cipher_name, get_mode_name, Padding},
            wrapper::{self},
            ANDROID_KEYSTORE,
        },
        core::error::{ToTpmError, TpmError},
    },
};
use async_std::sync::Mutex;
use async_trait::async_trait;
use robusta_jni::jni::JavaVM;
use tracing::{debug, info, instrument};

pub(crate) struct AndroidProviderFactory;

#[async_trait]
impl ProviderFactory for AndroidProviderFactory {
    fn get_name(&self) -> String {
        "AndroidProvider".to_owned()
    }

    async fn get_capabilities(&self, impl_config: ProviderImplConfig) -> ProviderConfig {
        ProviderConfig {
            min_security_level: SecurityLevel::Hardware,
            max_security_level: SecurityLevel::Hardware,
            supported_asym_spec: vec![AsymmetricKeySpec::Rsa(KeyBits::Bits2048)]
                .into_iter()
                .collect(),
            supported_ciphers: vec![Cipher::Aes(SymmetricMode::Gcm, KeyBits::Bits128)]
                .into_iter()
                .collect(),
            supported_hashes: HashSet::new(),
        }
    }

    async fn create_provider(&self, impl_config: ProviderImplConfig) -> Box<dyn ProviderImpl> {
        setup_logging();
        Box::new(AndroidProvider {
            java_vm: match impl_config {
                ProviderImplConfig::Android { vm } => vm,
                _ => panic!("Invalid ProviderImplConfig"),
            },
        })
    }
}

/// A TPM-based cryptographic provider for managing cryptographic keys and performing
/// cryptographic operations in an Android environment.
///
/// This provider uses the Android Keystore API to interact
/// with the Trusted Execution Environment (TEE), or the devices Secure Element(Like the Titan M chip in a Google Pixel)
/// for operations like signing, encryption, and decryption.
/// It provides a secure and hardware-backed solution for managing cryptographic keys and performing
/// cryptographic operations on Android.
pub(crate) struct AndroidProvider {
    java_vm: Arc<Mutex<JavaVM>>,
}

impl Debug for AndroidProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("AndroidProvider")
            .field("java_vm", &"opaque")
            .finish()
    }
}

/// Implementation of the `Provider` trait for the Android platform.
///
/// This struct provides methods for key generation, key loading, and module initialization
/// specific to Android.
#[async_trait]
impl ProviderImpl for AndroidProvider {
    #[instrument]
    async fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, SecurityModuleError> {
        let key_id = "key_id".to_owned();

        info!("generating key: {}", key_id);

        let vm = self.java_vm.lock().await;
        let thread = vm.attach_current_thread().expect("Thread attach failed");
        let env = vm.get_env().expect("Get env failed");

        info!("got env");

        // build up key specs
        let mut kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 1 | 2 | 4 | 8)
                .err_internal()?;

        match spec.cipher {
            Cipher::Aes(mode, size) => {
                kps_builder = kps_builder
                    .set_block_modes(&env, vec![get_mode_name(mode)?])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec!["NoPadding".to_owned()])
                    .err_internal()?
                    .set_key_size(&env, Into::<u32>::into(size) as i32)
                    .err_internal()?;
            }
            Cipher::Des => {
                kps_builder = kps_builder
                    .set_block_modes(&env, vec!["CBC".to_owned()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec!["NoPadding".to_owned()])
                    .err_internal()?;
            }
            Cipher::TripleDes(_) => {
                kps_builder = kps_builder
                    .set_block_modes(&env, vec!["CBC".to_owned()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec!["NoPadding".to_owned()])
                    .err_internal()?;
            }
            Cipher::Rc2(_) | Cipher::Camellia(_, _) | Cipher::Rc4 | Cipher::Chacha20(_) => {
                return Err(TpmError::UnsupportedOperation("not supported".to_owned()))?;
            }
        }

        kps_builder = kps_builder
            .set_is_strongbox_backed(&env, true)
            .err_internal()?;

        let kps = kps_builder.build(&env).err_internal()?;

        let kg = wrapper::key_generation::key_generator::jni::KeyGenerator::getInstance(
            &env,
            get_cipher_name(spec.cipher)?,
            ANDROID_KEYSTORE.to_owned(),
        )
        .err_internal()?;
        kg.init(&env, kps.raw.as_obj()).err_internal()?;

        kg.generateKey(&env).err_internal()?;

        debug!("key generated");

        Ok(KeyHandle {
            implementation: Box::new(AndroidKeyHandle {
                key_id: key_id.to_owned(),
                java_vm: self.java_vm.clone(),
                spec,
            }),
        })
    }

    async fn create_key_pair(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        let key_id = "key_id".to_owned();
        info!("generating key pair! {}", key_id);

        let vm = self.java_vm.lock().await;
        let thread = vm.attach_current_thread().unwrap();
        let env = vm.get_env().unwrap();

        // build up key specs
        let mut kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 1 | 2 | 4 | 8)
                .err_internal()?;

        match spec.asym_spec {
            AsymmetricKeySpec::Rsa(_key_bits) => {
                kps_builder = kps_builder
                    .set_digests(&env, vec![spec.signing_hash.into()])
                    .err_internal()?
                    .set_signature_paddings(&env, vec!["PKCS1".into()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec![Padding::PKCS1.into()])
                    .err_internal()?
                    .set_key_size(&env, _key_bits.into())
                    .err_internal()?;
            }
            AsymmetricKeySpec::Ecc { scheme, curve } => {
                kps_builder = kps_builder
                    .set_digests(&env, vec![spec.signing_hash.into()])
                    .err_internal()?;
            }
        };
        kps_builder = kps_builder
            .set_is_strongbox_backed(&env, true)
            .err_internal()?;

        let kps = kps_builder.build(&env).err_internal()?;

        let kpg = wrapper::key_generation::key_pair_generator::jni::KeyPairGenerator::getInstance(
            &env,
            spec.asym_spec.into(),
            ANDROID_KEYSTORE.to_owned(),
        )
        .err_internal()?;

        kpg.initialize(&env, kps.raw.as_obj()).err_internal()?;

        kpg.generateKeyPair(&env).err_internal()?;

        Ok(KeyPairHandle {
            implementation: Box::new(AndroidKeyPairHandle {
                key_id: key_id.to_owned(),
                java_vm: self.java_vm.clone(),
                spec,
            }),
        })
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
    async fn load_key(&mut self, key_id: String) -> Result<KeyHandle, SecurityModuleError> {
        // TODO: Somehow load the Keyspec from Storage
        todo!("load keyspec from storage")
    }

    #[instrument]
    async fn load_key_pair(
        &mut self,
        key_id: String,
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        // TODO: Somehow load the Keyspec from Storage
        todo!("load keyspec from storage")
    }

    #[instrument]
    async fn import_key(
        &mut self,
        spec: KeySpec,
        data: &[u8],
    ) -> Result<KeyHandle, SecurityModuleError> {
        // TODO: import key
        todo!("import key")
    }

    #[instrument]
    async fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        // TODO: import key pair
        todo!("import key pair")
    }

    #[instrument]
    async fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, SecurityModuleError> {
        // TODO: import public key
        todo!("import public key")
    }

    #[instrument]
    async fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<DHExchange, SecurityModuleError> {
        // TODO: start ephemeral dh exchange
        todo!("start ephemeral dh exchange")
    }

    fn provider_name(&self) -> String {
        "AndroidProvider".to_owned()
    }
}

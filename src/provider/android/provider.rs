use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel, Spec},
        crypto::algorithms::encryption::{AsymmetricKeySpec, Cipher},
        error::{CalError, ToCalError},
        traits::module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
        DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::CryptoHash,
    provider::android::{
        dh_exchange::AndroidDHExchange,
        key_handle::{AndroidKeyHandle, AndroidKeyPairHandle},
        utils::{
            get_asym_key_size, get_cipher_name, get_cipher_padding, get_key_size, get_mode_name,
            is_rsa, Padding,
        },
        wrapper::{self, context},
        ANDROID_KEYSTORE,
    },
    storage::{KeyData, StorageManager},
};

use anyhow::anyhow;
use itertools::Itertools;
use nanoid::nanoid;
use robusta_jni::jni::JavaVM;
use std::fmt::Debug;
use tracing::{info, instrument};

#[derive(Debug, Clone, Copy)]
pub(crate) struct AndroidProviderFactory {
    pub(crate) secure_element: bool,
}

impl ProviderFactory for AndroidProviderFactory {
    fn get_name(&self) -> Option<String> {
        if !wrapper::context::is_initialized() {
            return None;
        }
        if self.secure_element {
            if wrapper::context::has_strong_box().ok()? {
                Some("ANDROID_PROVIDER_SECURE_ELEMENT".to_owned())
            } else {
                None
            }
        } else {
            Some("ANDROID_PROVIDER".to_owned())
        }
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
        // check if android context is initialised
        if !wrapper::context::is_initialized() {
            info!("Android Context is not initialized, no android provider");
            return None;
        }

        // only check for Stronbox if secure element is enabled
        if self.secure_element && !wrapper::context::has_strong_box().ok()? {
            return None;
        }
        Some(ProviderConfig {
            min_security_level: SecurityLevel::Hardware,
            max_security_level: SecurityLevel::Hardware,
            supported_asym_spec: vec![
                AsymmetricKeySpec::RSA2048,
                AsymmetricKeySpec::RSA1024,
                AsymmetricKeySpec::Secp256k1,
            ]
            .into_iter()
            .collect(),
            supported_ciphers: vec![
                Cipher::AesCbc256,
                Cipher::AesCbc128,
                Cipher::AesGcm256,
                Cipher::AesGcm128,
            ]
            .into_iter()
            .collect(),
            supported_hashes: vec![CryptoHash::Sha2_256].into_iter().collect(),
        })
    }

    fn create_provider(
        &self,
        impl_config: ProviderImplConfig,
    ) -> Result<ProviderImplEnum, CalError> {
        if !wrapper::context::is_initialized() {
            return Err(CalError::initialization_error(
                "Android Context is not initialized".to_owned(),
            ));
        }

        let storage_manager =
            StorageManager::new(self.get_name().unwrap(), &impl_config.additional_config)?;

        Ok(ProviderImplEnum::from(AndroidProvider {
            impl_config,
            used_factory: *self,
            storage_manager,
        }))
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
#[derive(Clone)]
pub(crate) struct AndroidProvider {
    impl_config: ProviderImplConfig,
    used_factory: AndroidProviderFactory,
    storage_manager: Option<StorageManager>,
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
impl ProviderImpl for AndroidProvider {
    #[instrument]
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let key_id = nanoid!(10);

        info!("generating key: {}", key_id);

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        // build up key specs
        let mut kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 1 | 2 | 4 | 8)
                .err_internal()?;

        kps_builder = kps_builder
            .set_block_modes(&env, vec![get_mode_name(spec.cipher)?])
            .err_internal()?
            .set_encryption_paddings(&env, vec![get_cipher_padding(spec.cipher)?.into()])
            .err_internal()?
            .set_key_size(&env, get_key_size(spec.cipher)?)
            .err_internal()?
            .set_randomized_encryption_required(&env, false)
            .err_internal()?;

        kps_builder = kps_builder
            .set_is_strongbox_backed(&env, self.used_factory.secure_element)
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

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: None,
            public_data: None,
            additional_data: None,
            spec: Spec::KeySpec(spec),
        };

        let storage_manager = self.storage_manager.clone().filter(|_| !spec.ephemeral);

        if storage_manager.is_some() {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data)?;
        }

        Ok(KeyHandle {
            implementation: Into::into(AndroidKeyHandle {
                key_id,
                spec,
                storage_manager: storage_manager.clone(),
            }),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let key_id = nanoid!(10);
        info!("generating key pair: {}", key_id);

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        // build up key specs
        let mut kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 1 | 2 | 4 | 8)
                .err_internal()?;

        match is_rsa(spec.asym_spec) {
            true => {
                kps_builder = kps_builder
                    .set_digests(&env, vec![spec.signing_hash.into()])
                    .err_internal()?
                    .set_signature_paddings(&env, vec!["PKCS1".into()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec![Padding::PKCS1.into()])
                    .err_internal()?
                    .set_key_size(&env, get_asym_key_size(spec.asym_spec)?)
                    .err_internal()?;
            }
            false => {
                kps_builder = kps_builder
                    .set_digests(&env, vec![spec.signing_hash.into()])
                    .err_internal()?;
            }
        };
        kps_builder = kps_builder
            .set_is_strongbox_backed(&env, self.used_factory.secure_element)
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

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: None,
            public_data: None,
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        let storage_manager = self.storage_manager.clone().filter(|_| !spec.ephemeral);

        if storage_manager.is_some() {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data)?;
        }

        Ok(KeyPairHandle {
            implementation: Into::into(AndroidKeyPairHandle {
                key_id,
                spec,
                storage_manager: storage_manager.clone(),
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
    /// Returns `Ok(())` if the key loading is successful, otherwise returns an error of type `CalError`.
    #[instrument]
    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() {
            return Err(CalError::ephemeral_key_required());
        }

        let store_data = self.storage_manager.as_ref().unwrap().get(key_id.clone())?;

        match store_data.spec {
            Spec::KeySpec(spec) => Ok(KeyHandle {
                implementation: Into::into(AndroidKeyHandle {
                    key_id,
                    spec,
                    storage_manager: self.storage_manager.clone(),
                }),
            }),
            _ => Err(CalError::unsupported_algorithm(
                "Loading a Key Pair as a Symmetric Key".to_owned(),
            )),
        }
    }

    #[instrument]
    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() {
            return Err(CalError::ephemeral_key_required());
        }

        let store_data = self.storage_manager.as_ref().unwrap().get(key_id.clone())?;

        match store_data.spec {
            Spec::KeyPairSpec(spec) => Ok(KeyPairHandle {
                implementation: Into::into(AndroidKeyPairHandle {
                    key_id,
                    spec,
                    storage_manager: self.storage_manager.clone(),
                }),
            }),
            _ => Err(CalError::unsupported_algorithm(
                "Loading a symmetric Key as a Key Pair".to_owned(),
            )),
        }
    }

    #[instrument]
    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let id = nanoid!(10);

        let jdata = env.byte_array_from_slice(&data).err_internal()?;
        let algorithm = get_cipher_name(spec.cipher)?;
        let jalgorithm = env.new_string(algorithm).err_internal()?;
        let key = env
            .new_object(
                "javax/crypto/spec/SecretKeySpec",
                "([BLjava/lang/String;)V",
                &[jdata.into(), jalgorithm.into()],
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
                .set_is_strongbox_backed(&env, self.used_factory.secure_element)
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

        let storage_data = KeyData {
            id: id.clone(),
            secret_data: None,
            public_data: None,
            additional_data: None,
            spec: Spec::KeySpec(spec),
        };

        let storage_manager = self.storage_manager.clone().filter(|_| !spec.ephemeral);

        if storage_manager.is_some() {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(id.clone(), storage_data)?;
        }

        Ok(KeyHandle {
            implementation: Into::into(AndroidKeyHandle {
                key_id: id,
                spec,
                storage_manager: storage_manager.clone(),
            }),
        })
    }

    #[instrument]
    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        // TODO: import key pair
        todo!("import key pair")
    }

    #[instrument]
    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        // TODO: import public key
        todo!("import public key")
    }

    #[instrument]
    fn start_ephemeral_dh_exchange(&mut self, spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let key_id = nanoid!(10);
        info!("generating key pair for dh exchange: {}", key_id);

        let vm = context::android_context()?.vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        // build up key specs
        let mut kps_builder =
            wrapper::key_generation::builder::Builder::new(&env, key_id.to_owned(), 64)
                .err_internal()?;

        match is_rsa(spec.asym_spec) {
            true => {
                kps_builder = kps_builder
                    .set_digests(&env, vec![spec.signing_hash.into()])
                    .err_internal()?
                    .set_signature_paddings(&env, vec!["PKCS1".into()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec![Padding::PKCS1.into()])
                    .err_internal()?
                    .set_key_size(&env, get_asym_key_size(spec.asym_spec)?)
                    .err_internal()?;
            }
            false => {
                kps_builder = kps_builder
                    .set_digests(&env, vec![spec.signing_hash.into()])
                    .err_internal()?;
            }
        };
        kps_builder = kps_builder
            .set_is_strongbox_backed(&env, self.used_factory.secure_element)
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

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: None,
            public_data: None,
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        let storage_manager = self.storage_manager.clone().filter(|_| !spec.ephemeral);

        if storage_manager.is_some() {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data)?;
        }

        Ok(DHExchange {
            implementation: Into::into(AndroidDHExchange {
                key_id,
                spec,
                provider: self.clone(),
            }),
        })
    }

    #[instrument]
    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        if let Some(storage_manager) = self.storage_manager.as_ref() {
            storage_manager
                .get_all_keys()
                .into_iter()
                .process_results(|key_spec_tuple_iter| key_spec_tuple_iter.collect())
                .map_err(|err| {
                    CalError::failed_operation(
                        "At least metadata for one key could not be loaded.",
                        true,
                        Some(anyhow!(err)),
                    )
                })
        } else {
            Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot have stored keys",
                true,
                None,
            ))
        }
    }

    fn provider_name(&self) -> String {
        self.used_factory
            .get_name()
            .expect("a created Provider should have a name. This is a bug")
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        self.used_factory.get_capabilities(self.impl_config.clone())
    }
}

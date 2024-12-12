use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel, Spec},
        crypto::algorithms::encryption::{AsymmetricKeySpec, Cipher},
        error::{CalError, ToCalError},
        traits::module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
        DHExchange, KeyHandle, KeyPairHandle,
    },
    storage::{KeyData, StorageManager},
    tpm::android::{
        key_handle::{AndroidKeyHandle, AndroidKeyPairHandle},
        utils::{
            get_asym_key_size, get_cipher_name, get_cipher_padding, get_key_size, get_mode_name,
            is_rsa, Padding,
        },
        wrapper::{self},
        ANDROID_KEYSTORE,
    },
};

use nanoid::nanoid;
use robusta_jni::jni::JavaVM;
use std::{collections::HashSet, fmt::Debug};
use tracing::{debug, info, instrument};

#[derive(Debug, Clone, Copy)]
pub(crate) struct AndroidProviderFactory {
    pub(crate) secure_element: bool,
}

impl ProviderFactory for AndroidProviderFactory {
    fn get_name(&self) -> String {
        if self.secure_element {
            "ANDROID_PROVIDER_SECURE_ELEMENT".to_owned()
        } else {
            "ANDROID_PROVIDER".to_owned()
        }
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> Option<ProviderConfig> {
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
            supported_ciphers: vec![Cipher::AesCbc256].into_iter().collect(),
            supported_hashes: HashSet::new(),
        })
    }

    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        let storage_manager = if impl_config.ephemeral_keys {
            None
        } else {
            Some(StorageManager::new(
                self.get_name(),
                &impl_config.additional_config,
            ))
        };

        ProviderImplEnum::from(AndroidProvider {
            impl_config,
            used_factory: *self,
            storage_manager,
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
        if self.impl_config.ephemeral_keys && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let key_id = nanoid!(10);

        info!("generating key: {}", key_id);

        let vm = ndk_context::android_context().vm();
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

        debug!("key generated");

        Ok(KeyHandle {
            implementation: Into::into(AndroidKeyHandle {
                key_id,
                spec,
                storage_manager: storage_manager.clone(),
            }),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        if self.impl_config.ephemeral_keys && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let key_id = nanoid!(10);
        info!("generating key pair! {}", key_id);

        let vm = ndk_context::android_context().vm();
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
        if self.impl_config.ephemeral_keys {
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
        if self.impl_config.ephemeral_keys {
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
        if self.impl_config.ephemeral_keys && !spec.ephemeral {
            return Err(CalError::ephemeral_key_required());
        }

        let vm = ndk_context::android_context().vm();
        let vm = unsafe { JavaVM::from_raw(vm.cast()) }.err_internal()?;
        let env = vm.attach_current_thread().err_internal()?;

        let id = nanoid!(10);

        let key = wrapper::key_generation::secret_key_spec::jni::SecretKeySpec::new(
            &env,
            data.to_vec(),
            get_cipher_name(spec.cipher)?,
        )
        .err_internal()?;

        let key_store = wrapper::key_store::store::jni::KeyStore::getInstance(
            &env,
            ANDROID_KEYSTORE.to_owned(),
        )
        .err_internal()?;

        key_store
            .set_entry(&env, id.clone(), key.raw.as_obj(), None)
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
        // TODO: start ephemeral dh exchange
        todo!("start ephemeral dh exchange")
    }

    #[instrument]
    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        if self.impl_config.ephemeral_keys {
            return Err(CalError::ephemeral_key_required());
        }

        Ok(self.storage_manager.as_ref().unwrap().get_all_keys())
    }

    fn provider_name(&self) -> String {
        self.used_factory.get_name()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        self.used_factory.get_capabilities(self.impl_config.clone())
    }
}

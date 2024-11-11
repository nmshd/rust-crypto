use crate::{
    common::{
        config::{
            KeyPairSpec, KeySpec, ProviderConfig, ProviderImplConfig, SecurityLevel,
            SerializableSpec,
        },
        crypto::algorithms::{
            encryption::{AsymmetricKeySpec, Cipher, EccCurve, EccSigningScheme, SymmetricMode},
            KeyBits,
        },
        error::{CalError, KeyType, ToCalError},
        traits::module_provider::{ProviderFactory, ProviderImpl, ProviderImplEnum},
        DHExchange, KeyHandle, KeyPairHandle,
    },
    tpm::android::{
        key_handle::{AndroidKeyHandle, AndroidKeyPairHandle},
        utils::{get_cipher_name, get_cipher_padding, get_mode_name, Padding},
        wrapper::{self},
        ANDROID_KEYSTORE,
    },
};

use anyhow::anyhow;
use nanoid::nanoid;
use robusta_jni::jni::JavaVM;
use std::sync::Mutex;
use std::{collections::HashSet, fmt::Debug, sync::Arc};
use tracing::{debug, info, instrument};

pub(crate) struct AndroidProviderFactory {}

impl ProviderFactory for AndroidProviderFactory {
    fn get_name(&self) -> String {
        "ANDROID_PROVIDER".to_owned()
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> ProviderConfig {
        ProviderConfig {
            min_security_level: SecurityLevel::Hardware,
            max_security_level: SecurityLevel::Hardware,
            supported_asym_spec: vec![
                AsymmetricKeySpec::Rsa(KeyBits::Bits2048),
                AsymmetricKeySpec::Rsa(KeyBits::Bits1024),
                AsymmetricKeySpec::Ecc {
                    scheme: EccSigningScheme::EcDsa,
                    curve: EccCurve::Secp256k1,
                },
            ]
            .into_iter()
            .collect(),
            supported_ciphers: vec![Cipher::Aes(SymmetricMode::Cbc, KeyBits::Bits256)]
                .into_iter()
                .collect(),
            supported_hashes: HashSet::new(),
        }
    }

    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        ProviderImplEnum::from(AndroidProvider {
            java_vm: impl_config
                .java_vm
                .clone()
                .expect("no jvm provided")
                .downcast::<Mutex<JavaVM>>()
                .expect("downcast failed"),
            impl_config,
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
impl ProviderImpl for AndroidProvider {
    #[instrument]
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        let key_id = nanoid!(10);

        info!("generating key: {}", key_id);

        let vm = self.java_vm.lock().unwrap();
        let _attach_guard = vm.attach_current_thread().err_internal()?;
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
                    .set_encryption_paddings(&env, vec![get_cipher_padding(spec.cipher)])
                    .err_internal()?
                    .set_key_size(&env, Into::<u32>::into(size) as i32)
                    .err_internal()?;
            }
            Cipher::Des => {
                kps_builder = kps_builder
                    .set_block_modes(&env, vec!["CBC".to_owned()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec![get_cipher_padding(spec.cipher)])
                    .err_internal()?;
            }
            Cipher::TripleDes(_) => {
                kps_builder = kps_builder
                    .set_block_modes(&env, vec!["CBC".to_owned()])
                    .err_internal()?
                    .set_encryption_paddings(&env, vec![get_cipher_padding(spec.cipher)])
                    .err_internal()?;
            }
            Cipher::Rc2(_) | Cipher::Camellia(_, _) | Cipher::Rc4 | Cipher::Chacha20(_) => {
                return Err(CalError::unsupported_algorithm(format!(
                    "{:?}",
                    spec.cipher
                )))?;
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

        let encoded_spec = bincode::serialize(&SerializableSpec::KeySpec(spec))
            .map_err(|e| CalError::other(anyhow!(e)))?;
        pollster::block_on((self.impl_config.store_fn)(key_id.clone(), encoded_spec));

        debug!("key generated");

        Ok(KeyHandle {
            implementation: Into::into(AndroidKeyHandle {
                key_id,
                java_vm: self.java_vm.clone(),
                spec,
                impl_config: self.impl_config.clone(),
            }),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        let key_id = nanoid!(10);
        info!("generating key pair! {}", key_id);

        let vm = self.java_vm.lock().unwrap();
        let _attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

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
            AsymmetricKeySpec::Ecc {
                scheme: _,
                curve: _,
            } => {
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

        // TODO: Store the KeySpec in Storage
        let encoded = bincode::serialize(&SerializableSpec::KeyPairSpec(spec))
            .map_err(|e| CalError::other(anyhow!(e)))?;
        pollster::block_on((self.impl_config.store_fn)(key_id.clone(), encoded));

        Ok(KeyPairHandle {
            implementation: Into::into(AndroidKeyPairHandle {
                key_id,
                java_vm: self.java_vm.clone(),
                spec,
                impl_config: self.impl_config.clone(),
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
        let encoded = pollster::block_on((self.impl_config.get_fn)(key_id.clone()))
            .ok_or(CalError::missing_key(key_id.clone(), KeyType::Symmetric))?;

        let spec: SerializableSpec =
            bincode::deserialize(&encoded).map_err(|e| CalError::other(anyhow!(e)))?;
        match spec {
            SerializableSpec::KeySpec(spec) => Ok(KeyHandle {
                implementation: Into::into(AndroidKeyHandle {
                    key_id,
                    java_vm: self.java_vm.clone(),
                    spec,
                    impl_config: self.impl_config.clone(),
                }),
            }),
            _ => Err(CalError::unsupported_algorithm(
                "Loading a Key Pair as a Symmetric Key".to_owned(),
            )),
        }
    }

    #[instrument]
    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        let encoded = pollster::block_on((self.impl_config.get_fn)(key_id.clone())).ok_or(
            CalError::missing_key(key_id.clone(), KeyType::PublicAndPrivate),
        )?;

        let spec: SerializableSpec =
            bincode::deserialize(&encoded).map_err(|e| CalError::other(anyhow!(e)))?;
        match spec {
            SerializableSpec::KeyPairSpec(spec) => Ok(KeyPairHandle {
                implementation: Into::into(AndroidKeyPairHandle {
                    key_id,
                    java_vm: self.java_vm.clone(),
                    spec,
                    impl_config: self.impl_config.clone(),
                }),
            }),
            _ => Err(CalError::unsupported_algorithm(
                "Loading a symmetric Key as a Key Pair".to_owned(),
            )),
        }
    }

    #[instrument]
    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        let vm = self.java_vm.lock().unwrap();
        let _attach_guard = vm.attach_current_thread().err_internal()?;
        let env = vm.get_env().err_internal()?;

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

        Ok(KeyHandle {
            implementation: Into::into(AndroidKeyHandle {
                key_id: id,
                java_vm: self.java_vm.clone(),
                spec,
                impl_config: self.impl_config.clone(),
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

    fn provider_name(&self) -> String {
        "ANDROID_PROVIDER".to_owned()
    }

    fn get_capabilities(&self) -> ProviderConfig {
        AndroidProviderFactory {}.get_capabilities(self.impl_config.clone())
    }
}

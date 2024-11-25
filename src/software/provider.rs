use super::{
    key_handle::{SoftwareKeyHandle, SoftwareKeyPairHandle},
    SoftwareProvider, SoftwareProviderFactory,
};
use crate::common::{
    config::{KeyPairSpec, KeySpec, ProviderConfig, SerializableSpec},
    error::CalError,
    traits::{
        key_handle::{DHKeyExchangeImpl, KeyHandleImplEnum},
        module_provider::{ProviderFactory, ProviderImpl},
    },
    DHExchange, KeyHandle, KeyPairHandle,
};
use nanoid::nanoid;
use ring::{
    aead::{Algorithm, LessSafeKey, UnboundKey, AES_256_GCM},
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};
use serde_json::to_vec;
use smol::block_on;
use std::sync::Arc;

impl ProviderImpl for SoftwareProvider {
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        let key_id = nanoid!(10);

        // Initialize the system random generator
        let rng = SystemRandom::new();
        let algo: &Algorithm = spec.cipher.into();

        // Generate the symmetric key data
        let mut key_data = vec![0u8; algo.key_len()];
        rng.fill(&mut key_data)
            .expect("Failed to generate symmetric key");

        // Create an UnboundKey for the AES-GCM encryption
        let unbound_key = UnboundKey::new(algo, &key_data).map_err(|_| {
            CalError::failed_operation("Failed to create unbound AES key".to_owned(), true, None)
        })?;

        block_on((self.impl_config.store_fn)(
            key_id.clone(),
            to_vec(&SerializableSpec::KeySpec(spec)).unwrap(),
        ));

        #[cfg(feature = "software-keystore")]
        self.save_key(key_id.clone(), &key_data)?;

        // Wrap it in a LessSafeKey for easier encryption/decryption
        let less_safe_key = Arc::new(LessSafeKey::new(unbound_key));

        // Initialize SoftwareKeyHandle with the LessSafeKey
        let handle = SoftwareKeyHandle {
            key_id,
            key: less_safe_key,
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        #[cfg(feature = "software-keystore")]
        {
            let key_bytes = self.load_key_from_store(key_id.clone())?;

            let key_spec = block_on((self.impl_config.get_fn)(key_id.clone())).unwrap();

            // Deserialize the Vec<u8> into SerializableSpec using serde_json
            let deserialized_spec: SerializableSpec = serde_json::from_slice(&key_spec)
                .map_err(|e| {
                    CalError::failed_operation(
                        format!("Deserialization error for key '{}': {:?}", key_id, e),
                        false,
                        Some(e.into()),
                    )
                })
                .unwrap();

            let spec = match deserialized_spec {
                SerializableSpec::KeySpec(key_spec) => key_spec,
                SerializableSpec::KeyPairSpec(_) => todo!(),
            };

            // Create an UnboundKey for the AES-GCM encryption
            let unbound_key = UnboundKey::new(spec.cipher.into(), &key_bytes).map_err(|_| {
                CalError::failed_operation(
                    "Failed to create unbound AES key".to_owned(),
                    true,
                    None,
                )
            })?;

            // Wrap it in a LessSafeKey for easier encryption/decryption
            let less_safe_key = Arc::new(LessSafeKey::new(unbound_key));

            // Initialize SoftwareKeyHandle with the LessSafeKey
            let handle = SoftwareKeyHandle {
                key_id,
                key: less_safe_key,
            };

            Ok(KeyHandle {
                implementation: handle.into(),
            })
        }
        #[cfg(not(feature = "software-keystore"))]
        {
            Err(CalError::not_implemented())
        }
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        let key_id = nanoid!(10);

        // Generate ECC key pair using ring's SystemRandom for asymmetric keys
        let rng = SystemRandom::new();
        let algorithm: &EcdsaSigningAlgorithm = spec.asym_spec.into();
        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("Failed to generate private key");

        // Create an EcdsaKeyPair from the PKCS#8-encoded private key
        let key_pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8_bytes.as_ref(), &rng)
            .expect("Failed to parse key pair");

        block_on((self.impl_config.store_fn)(
            key_id.clone(),
            to_vec(&SerializableSpec::KeyPairSpec(spec)).unwrap(),
        ));

        #[cfg(feature = "software-keystore")]
        self.save_key_pair(key_id.clone(), pkcs8_bytes.as_ref())?;

        // Extract the public key bytes
        let public_key = key_pair.public_key().as_ref().to_vec();

        // Initialize SoftwareKeyPairHandle with the private and public key bytes
        let handle =
            SoftwareKeyPairHandle::new(key_id, spec, pkcs8_bytes.as_ref().to_vec(), public_key)?;

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        #[cfg(feature = "software-keystore")]
        {
            // Simulate loading key data from storage
            let rng = SystemRandom::new();

            let key_pair: SerializableSpec = self.load_key_metadata(key_id.clone()).unwrap();
            let spec: KeyPairSpec = match key_pair {
                SerializableSpec::KeySpec(_) => todo!(),
                SerializableSpec::KeyPairSpec(key_pair_spec) => key_pair_spec,
            };

            #[cfg(feature = "software-keystore")]
            let pkcs8_bytes = self.load_key_from_store(key_id.clone())?;

            let key_pair = EcdsaKeyPair::from_pkcs8(spec.into(), pkcs8_bytes.as_ref(), &rng)
                .expect("Failed to parse key pair");

            // Initialize SoftwareKeyPairHandle with loaded private and public key bytes
            let handle = SoftwareKeyPairHandle::new(
                key_id,
                spec,
                pkcs8_bytes,
                key_pair.public_key().as_ref().to_vec(),
            )?;

            Ok(KeyPairHandle {
                implementation: handle.into(),
            })
        }
        #[cfg(not(feature = "software-keystore"))]
        {
            Err(CalError::not_implemented())
        }
    }

    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        let key_id = nanoid!(10);

        // Initialize SoftwareKeyHandle with the raw key data
        let handle = SoftwareKeyHandle::new(key_id, Some(spec), data.to_vec())?;

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        let key_id = nanoid!(10);

        // Initialize SoftwareKeyPairHandle with separate private and public key bytes
        let handle =
            SoftwareKeyPairHandle::new(key_id, spec, private_key.to_vec(), public_key.to_vec())?;

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        let key_id = nanoid!(10);
        let handle = SoftwareKeyPairHandle::new_public_only(key_id, spec, public_key.to_vec())?;

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn start_ephemeral_dh_exchange(&mut self, _spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        let key_id = nanoid!(10); // Generate a unique key ID

        // Initialize the SoftwareDHExchange instance
        let dh_exchange =
            SoftwareDHExchange::new(key_id).expect("Failed to initialize DH exchange");

        // Wrap in DHExchange and return
        Ok(DHExchange {
            implementation: dh_exchange.into(),
        })
    }

    fn provider_name(&self) -> String {
        "SoftwareProvider".to_owned()
    }

    fn get_capabilities(&self) ->Option<ProviderConfig> {
        SoftwareProviderFactory::default().get_capabilities(self.impl_config.clone())
    }
}

#[derive(Debug)]
pub(crate) struct SoftwareDHExchange {
    key_id: String,
    private_key: Option<EphemeralPrivateKey>,
    public_key: PublicKey,
}

impl SoftwareDHExchange {
    pub fn new(key_id: String) -> Result<Self, CalError> {
        let rng = SystemRandom::new();

        // Generate an ephemeral private key for DH using X25519
        let private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .expect("Failed to generate DH private key");

        // Compute the associated public key
        let public_key = private_key
            .compute_public_key()
            .expect("Failed to compute DH public key");

        Ok(Self {
            key_id,
            private_key: Some(private_key),
            public_key,
        })
    }
}

impl DHKeyExchangeImpl for SoftwareDHExchange {
    /// Returns the public key as bytes for sharing with the peer
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.as_ref().to_vec())
    }

    /// Computes an intermediate shared secret with an external public key (consumes `self`)
    fn add_external(&mut self, external_key: &[u8]) -> Result<Vec<u8>, CalError> {
        // Parse the external public key
        let peer_public_key = UnparsedPublicKey::new(&X25519, external_key);

        if self.private_key.is_none() {
            return Err(CalError::failed_operation(
                "No private key available".to_string(),
                true,
                None,
            ));
        };

        // Perform key agreement to produce an intermediate shared secret
        agreement::agree_ephemeral(
            self.private_key.take().unwrap(),
            &peer_public_key,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
        .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?
    }

    /// Computes the final shared secret, derives a symmetric key, and returns it as a key handle
    fn add_external_final(&mut self, external_key: &[u8]) -> Result<KeyHandleImplEnum, CalError> {
        // Parse the final external public key
        let peer_public_key = UnparsedPublicKey::new(&X25519, external_key);

        if self.private_key.is_none() {
            return Err(CalError::failed_operation(
                "No private key available".to_string(),
                true,
                None,
            ));
        };

        // Perform key agreement to produce the final shared secret
        let shared_secret = agreement::agree_ephemeral(
            self.private_key.take().unwrap(),
            &peer_public_key,
            |shared_secret| shared_secret.to_vec(),
        )
        .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;

        // Derive a symmetric key (AES-256) from the shared secret
        let key_material = &shared_secret[0..32]; // Use the first 32 bytes as AES-256 key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_material)
            .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?;
        let symmetric_key = Arc::new(LessSafeKey::new(unbound_key));

        // Return the symmetric key wrapped in KeyHandleImplEnum
        Ok(KeyHandleImplEnum::SoftwareKeyHandle(SoftwareKeyHandle {
            key_id: self.key_id.clone(),
            key: symmetric_key,
        }))
    }
}

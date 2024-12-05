use super::{
    key_handle::{SoftwareKeyHandle, SoftwareKeyPairHandle},
    SoftwareProvider, SoftwareProviderFactory, StorageManager,
};
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, Spec},
        crypto::algorithms::encryption::AsymmetricKeySpec,
        error::CalError,
        traits::{
            key_handle::{DHKeyExchangeImpl, KeyHandleImplEnum},
            module_provider::{ProviderFactory, ProviderImpl},
        },
        DHExchange, KeyHandle, KeyPairHandle,
    },
    storage::KeyData,
};
use nanoid::nanoid;
use ring::{
    aead::{Algorithm, LessSafeKey, UnboundKey, AES_256_GCM},
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};
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

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: Some(key_data),
            public_data: None,
            additional_data: None,
            spec: Spec::KeySpec(spec),
        };

        self.storage_manager.store(key_id.clone(), storage_data)?;

        // Wrap it in a LessSafeKey for easier encryption/decryption
        let less_safe_key = Arc::new(LessSafeKey::new(unbound_key));

        // Initialize SoftwareKeyHandle with the LessSafeKey
        let handle = SoftwareKeyHandle {
            key_id,
            key: less_safe_key,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        let storage_data = self.storage_manager.get(key_id.clone())?;

        let spec = if let Spec::KeySpec(spec) = storage_data.spec {
            spec
        } else {
            return Err(CalError::failed_operation(
                "Trying to load KeyPair as symmetric Key".to_owned(),
                true,
                None,
            ));
        };

        let key_data = match storage_data.secret_data {
            Some(v) => v,
            _ => {
                return Err(CalError::failed_operation(
                    "no sensitive data for key found".to_owned(),
                    true,
                    None,
                ))
            }
        };

        // Create an UnboundKey for the AES-GCM encryption
        let unbound_key = UnboundKey::new(spec.cipher.into(), &key_data).map_err(|_| {
            CalError::failed_operation("Failed to create unbound AES key".to_owned(), true, None)
        })?;

        // Wrap it in a LessSafeKey for easier encryption/decryption
        let less_safe_key = Arc::new(LessSafeKey::new(unbound_key));

        // Initialize SoftwareKeyHandle with the LessSafeKey
        let handle = SoftwareKeyHandle {
            key_id,
            key: less_safe_key,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        let key_id = nanoid!(10);

        let storage_data = if let AsymmetricKeySpec::Curve25519 = spec.asym_spec {
            let keypair = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::default());
            KeyData {
                id: key_id.clone(),
                secret_data: Some(keypair.sk.to_vec()),
                public_data: Some(keypair.pk.to_vec()),
                additional_data: None,
                spec: Spec::KeyPairSpec(spec),
            }
        } else {
            // Generate ECC key pair using ring's SystemRandom for asymmetric keys
            let rng = SystemRandom::new();
            let algorithm: &EcdsaSigningAlgorithm = spec.asym_spec.into();
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(algorithm, &rng)
                .expect("Failed to generate private key");

            // Create an EcdsaKeyPair from the PKCS#8-encoded private key
            let key_pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8_bytes.as_ref(), &rng)
                .expect("Failed to parse key pair");

            KeyData {
                id: key_id.clone(),
                secret_data: Some(pkcs8_bytes.as_ref().to_vec()),
                public_data: Some(key_pair.public_key().as_ref().to_vec()),
                additional_data: None,
                spec: Spec::KeyPairSpec(spec),
            }
        };

        self.storage_manager
            .store(key_id.clone(), storage_data.clone())?;

        // Initialize SoftwareKeyPairHandle with the private and public key bytes
        let handle = SoftwareKeyPairHandle {
            key_id,
            spec,
            signing_key: storage_data.secret_data,
            public_key: storage_data.public_data.unwrap(),
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        let storage_data = self.storage_manager.get(key_id.clone())?;

        let spec = if let Spec::KeyPairSpec(spec) = storage_data.spec {
            spec
        } else {
            return Err(CalError::failed_operation(
                "Trying to load symmetric Key as KeyPair".to_owned(),
                true,
                None,
            ));
        };

        let key_data = storage_data.secret_data;

        let public_key = match storage_data.public_data {
            Some(v) => v,
            None => {
                return Err(CalError::failed_operation(
                    "no public data for KeyPair found".to_owned(),
                    true,
                    None,
                ))
            }
        };

        let handle = SoftwareKeyPairHandle {
            key_id,
            spec,
            signing_key: key_data,
            public_key,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        let key_id = nanoid!(10);

        // Initialize SoftwareKeyHandle with the raw key data
        let handle = SoftwareKeyHandle::new(
            key_id.clone(),
            Some(spec),
            data.to_vec(),
            self.storage_manager.clone(),
        )?;

        // store key
        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: Some(data.to_vec()),
            public_data: None,
            additional_data: None,
            spec: Spec::KeySpec(spec),
        };

        self.storage_manager.store(key_id.clone(), storage_data)?;

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
        let handle = SoftwareKeyPairHandle {
            key_id: key_id.clone(),
            spec,
            signing_key: Some(private_key.to_vec()),
            public_key: public_key.to_vec(),
            storage_manager: self.storage_manager.clone(),
        };

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: Some(private_key.to_vec()),
            public_data: Some(public_key.to_vec()),
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        self.storage_manager.store(key_id.clone(), storage_data)?;

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
        let handle = SoftwareKeyPairHandle {
            key_id: key_id.clone(),
            spec,
            public_key: public_key.to_vec(),
            signing_key: None,
            storage_manager: self.storage_manager.clone(),
        };

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: None,
            public_data: Some(public_key.to_vec()),
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        self.storage_manager.store(key_id.clone(), storage_data)?;

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn start_ephemeral_dh_exchange(&mut self, _spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        let key_id = nanoid!(10); // Generate a unique key ID

        // Initialize the SoftwareDHExchange instance
        let dh_exchange = SoftwareDHExchange::new(key_id, self.storage_manager.clone())
            .expect("Failed to initialize DH exchange");

        // Wrap in DHExchange and return
        Ok(DHExchange {
            implementation: dh_exchange.into(),
        })
    }

    fn get_all_keys(&self) -> Result<Vec<Spec>, CalError> {
        Ok(self.storage_manager.get_all_keys())
    }

    fn provider_name(&self) -> String {
        "SoftwareProvider".to_owned()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        SoftwareProviderFactory::default().get_capabilities(self.impl_config.clone())
    }
}

#[derive(Debug)]
pub(crate) struct SoftwareDHExchange {
    key_id: String,
    private_key: Option<EphemeralPrivateKey>,
    public_key: PublicKey,
    storage_manager: StorageManager,
}

impl SoftwareDHExchange {
    pub fn new(key_id: String, storage_manager: StorageManager) -> Result<Self, CalError> {
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
            storage_manager,
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
    fn add_external_final(&mut self, external_key: &[u8]) -> Result<KeyHandle, CalError> {
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
        Ok(KeyHandle {
            implementation: KeyHandleImplEnum::SoftwareKeyHandle(SoftwareKeyHandle {
                key_id: self.key_id.clone(),
                key: symmetric_key,
                storage_manager: self.storage_manager.clone(),
            }),
        })
    }
}

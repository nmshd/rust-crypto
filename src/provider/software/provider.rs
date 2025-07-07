use super::{
    key_handle::{SoftwareKeyHandle, SoftwareKeyPairHandle},
    SoftwareProvider, SoftwareProviderFactory, StorageManager,
};
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, Spec},
        crypto::algorithms::encryption::{AsymmetricKeySpec, Cipher},
        error::CalError,
        traits::{
            key_handle::DHKeyExchangeImpl,
            module_provider::{ProviderFactory, ProviderImpl},
        },
        DHExchange, KeyHandle, KeyPairHandle,
    },
    prelude::{CryptoHash, KDF},
    storage::KeyData,
};
use anyhow::anyhow;
use argon2::{
    password_hash::SaltString, Argon2, Params, PasswordHasher, MAX_SALT_LEN, MIN_SALT_LEN,
};
use blake2::{Blake2b512, Digest};
use itertools::Itertools;
use nanoid::nanoid;
use p256::{
    ecdh::diffie_hellman, elliptic_curve::rand_core::OsRng, PublicKey as P256PublicKey,
    SecretKey as P256SecretKey,
};
use ring::{
    aead::Algorithm,
    digest::{digest, SHA256, SHA384, SHA512, SHA512_256},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use tracing::{error, info, trace};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

impl ProviderImpl for SoftwareProvider {
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        info!("creating key");
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot create non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot create non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id = nanoid!(10);

        // Initialize the system random generator
        let rng = SystemRandom::new();

        // Handle XChaCha20Poly1305 specially since it's not supported by ring
        let key_data = if spec.cipher == Cipher::XChaCha20Poly1305 {
            // XChaCha20Poly1305 requires a 256-bit (32-byte) key
            let mut key_data = vec![0u8; 32];
            rng.fill(&mut key_data).map_err(|e| {
                error!("Failed to generate XChaCha20Poly1305 key");
                CalError::failed_operation(
                    "Failed to generate XChaCha20Poly1305 key".to_owned(),
                    false,
                    Some(anyhow!(e)),
                )
            })?;
            key_data
        } else {
            // For ring-supported ciphers, use the existing From implementation
            let algo: &Algorithm = spec.cipher.into();

            // Generate the symmetric key data
            let mut key_data = vec![0u8; algo.key_len()];
            rng.fill(&mut key_data).map_err(|e| {
                error!("Failed to generate symmetric key");
                CalError::failed_operation(
                    "Failed to generate symmetric key".to_owned(),
                    false,
                    Some(anyhow!(e)),
                )
            })?;
            key_data
        };

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: Some(key_data.clone()),
            public_data: None,
            additional_data: None,
            spec: Spec::KeySpec(spec),
        };

        if self.storage_manager.is_some() && !spec.ephemeral {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data)?;
        }

        // If the key is ephemeral, don't even pass the storage manager
        let storage_manager = if spec.ephemeral {
            None
        } else {
            self.storage_manager.clone()
        };

        // Initialize SoftwareKeyHandle with the key data
        let handle = SoftwareKeyHandle {
            key_id,
            key: key_data,
            storage_manager: storage_manager.clone(),
            spec,
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() {
            error!("This is an ephemeral provider, it cannot load keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot load keys".to_owned(),
                true,
                None,
            ));
        }

        let storage_data = self.storage_manager.as_ref().unwrap().get(key_id.clone())?;

        let Spec::KeySpec(spec) = storage_data.spec else {
            error!("Trying to load KeyPair as symmetric Key");
            return Err(CalError::failed_operation(
                "Trying to load KeyPair as symmetric Key".to_owned(),
                true,
                None,
            ));
        };

        let Some(key_data) = storage_data.secret_data else {
            error!("No sensitive data for key found.");
            return Err(CalError::failed_operation(
                "No sensitive data for key found.".to_owned(),
                true,
                None,
            ));
        };

        // Initialize SoftwareKeyHandle with the LessSafeKey
        let handle = SoftwareKeyHandle {
            key_id,
            key: key_data,
            storage_manager: self.storage_manager.clone(),
            spec,
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        info!("creating key pair");
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot create non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot create non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

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
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(algorithm, &rng).map_err(|e| {
                error!("Failed to generate private key");
                CalError::failed_operation(
                    "Failed to generate private key".to_owned(),
                    false,
                    Some(anyhow!(e)),
                )
            })?;

            // Create an EcdsaKeyPair from the PKCS#8-encoded private key
            let key_pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8_bytes.as_ref(), &rng)
                .map_err(|e| {
                    error!("Failed to parse key pair");
                    CalError::failed_operation(
                        "Failed to parse key pair".to_owned(),
                        false,
                        Some(anyhow!(e)),
                    )
                })?;

            KeyData {
                id: key_id.clone(),
                secret_data: Some(pkcs8_bytes.as_ref().to_vec()),
                public_data: Some(key_pair.public_key().as_ref().to_vec()),
                additional_data: None,
                spec: Spec::KeyPairSpec(spec),
            }
        };

        if self.storage_manager.is_some() && !spec.ephemeral {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data.clone())?;
        }

        let storage_manager = if spec.ephemeral {
            None
        } else {
            self.storage_manager.clone()
        };

        // Initialize SoftwareKeyPairHandle with the private and public key bytes
        let handle = SoftwareKeyPairHandle {
            key_id,
            spec,
            signing_key: storage_data.secret_data,
            public_key: storage_data.public_data.unwrap(),
            storage_manager: storage_manager.clone(),
        };

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() {
            error!("This is an ephemeral provider, it cannot load keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot load keys".to_owned(),
                true,
                None,
            ));
        }

        let storage_data = self.storage_manager.as_ref().unwrap().get(key_id.clone())?;

        let Spec::KeyPairSpec(spec) = storage_data.spec else {
            error!("Trying to load symmetric Key as KeyPair");
            return Err(CalError::failed_operation(
                "Trying to load symmetric Key as KeyPair".to_owned(),
                true,
                None,
            ));
        };

        let key_data = storage_data.secret_data;

        let Some(public_key) = storage_data.public_data else {
            error!("no public data for KeyPair found");
            return Err(CalError::failed_operation(
                "no public data for KeyPair found".to_owned(),
                true,
                None,
            ));
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
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot import non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot import non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id = nanoid!(10);

        let storage_manager = if spec.ephemeral {
            None
        } else {
            self.storage_manager.clone()
        };

        // Initialize SoftwareKeyHandle with the raw key data
        let handle =
            SoftwareKeyHandle::new(key_id.clone(), spec, data.to_vec(), storage_manager.clone())?;

        // store key
        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: Some(data.to_vec()),
            public_data: None,
            additional_data: None,
            spec: Spec::KeySpec(spec),
        };

        if self.storage_manager.is_some() && !spec.ephemeral {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data)?;
        }

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
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot import non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot import non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id = nanoid!(10);

        let storage_manager = if spec.ephemeral {
            None
        } else {
            self.storage_manager.clone()
        };

        // Initialize SoftwareKeyPairHandle with separate private and public key bytes
        let handle = SoftwareKeyPairHandle {
            key_id: key_id.clone(),
            spec,
            signing_key: Some(private_key.to_vec()),
            public_key: public_key.to_vec(),
            storage_manager: storage_manager.clone(),
        };

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: Some(private_key.to_vec()),
            public_data: Some(public_key.to_vec()),
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        if self.storage_manager.is_some() && !spec.ephemeral {
            self.storage_manager
                .as_ref()
                .unwrap()
                .store(key_id.clone(), storage_data)?;
        }

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot import non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot import non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id = nanoid!(10);

        let storage_manager = if spec.ephemeral {
            None
        } else {
            self.storage_manager.clone()
        };

        let handle = SoftwareKeyPairHandle {
            key_id: key_id.clone(),
            spec,
            public_key: public_key.to_vec(),
            signing_key: None,
            storage_manager: storage_manager.clone(),
        };

        let storage_data = KeyData {
            id: key_id.clone(),
            secret_data: None,
            public_data: Some(public_key.to_vec()),
            additional_data: None,
            spec: Spec::KeyPairSpec(spec),
        };

        storage_manager
            .as_ref()
            .map(|s| s.store(key_id.clone(), storage_data))
            .transpose()?;

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
    }

    fn start_ephemeral_dh_exchange(&mut self, spec: KeyPairSpec) -> Result<DHExchange, CalError> {
        let key_id = nanoid!(10); // Generate a unique key ID

        // Initialize the SoftwareDHExchange instance
        let dh_exchange = SoftwareDHExchange::new(key_id, self.storage_manager.clone(), spec)?;

        // Wrap in DHExchange and return
        Ok(DHExchange {
            implementation: dh_exchange.into(),
        })
    }

    /// [DEPRECATED]: Creates a DHExchange from existing key pair bytes instead of generating a new one.
    fn dh_exchange_from_keys(
        &mut self,
        public_key: &[u8],
        private_key: &[u8],
        spec: KeyPairSpec,
    ) -> Result<DHExchange, CalError> {
        let key_id = nanoid!(10); // Generate a unique key ID

        // Initialize SoftwareDHExchange from existing keys
        let dh_exchange = SoftwareDHExchange::from_keypair_bytes(
            key_id,
            private_key,
            public_key,
            self.storage_manager.clone(),
            spec,
        )?;

        // Wrap in DHExchange and return
        Ok(DHExchange {
            implementation: dh_exchange.into(),
        })
    }

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
        "SoftwareProvider".to_owned()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        SoftwareProviderFactory::default().get_capabilities(self.impl_config.clone())
    }

    /// Derives a high-entropy key from a low-entropy password and a unique salt.
    ///
    /// Only Argon2 is currently supported.
    fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        algorithm: KeySpec,
        kdf: KDF,
    ) -> Result<KeyHandle, CalError> {
        let (argo2_algorithm, argon2_option) = match kdf {
            KDF::Argon2i(o) => (argon2::Algorithm::Argon2i, o),
            KDF::Argon2d(o) => (argon2::Algorithm::Argon2d, o),
            KDF::Argon2id(o) => (argon2::Algorithm::Argon2id, o),
            // _ => return Err(CalError::not_implemented()),
        };

        if salt.len() < 8 || salt.len() > 64 {
            return Err(CalError::bad_parameter(
                format!(
                    "Wrong salt length. Does not match requirement: {} <= {} <= {}",
                    MIN_SALT_LEN,
                    salt.len(),
                    MAX_SALT_LEN
                ),
                true,
                None,
            ));
        }

        // Determine key length based on cipher
        let key_length = match algorithm.cipher {
            Cipher::AesGcm128 => 16,
            Cipher::AesGcm256 | Cipher::XChaCha20Poly1305 => 32,
            _ => {
                return Err(CalError::bad_parameter(
                    "Unsupported cipher for key derivation".to_string(),
                    true,
                    None,
                ))
            }
        };

        // Create Argon2 with specified algorithm
        let argon2 = Argon2::new(
            argo2_algorithm,
            argon2::Version::V0x13, // Latest version
            Params::new(
                argon2_option.memory,      // m_cost (memory)
                argon2_option.iterations,  // t_cost (iterations)
                argon2_option.parallelism, // p_cost (parallelism)
                Some(key_length),
            )
            .map_err(|e| {
                CalError::failed_operation(format!("Invalid Argon2 parameters: {}", e), true, None)
            })?,
        );

        let salt_str = SaltString::encode_b64(salt)
            .map_err(|_| CalError::failed_operation("Failed to encode salt", true, None))?;

        // Perform password hashing with specified parameters
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_str)
            .map_err(|e| {
                error!("Failed derivation of key with argon2.");
                CalError::failed_operation(
                    "Failed derivation of key with argon2.".to_owned(),
                    false,
                    Some(anyhow!(e)),
                )
            })?;

        // Extract the raw hash output and truncate to the required key length
        let derived_key = password_hash.hash.unwrap().as_bytes()[..key_length].to_vec();

        let key_id = nanoid!(10);
        let handle = SoftwareKeyHandle {
            key_id: key_id.clone(),
            spec: algorithm,
            key: derived_key,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn derive_key_from_base(
        &self,
        base_key: &[u8],
        key_id: u64,
        context: &str,
        algorithm: KeySpec,
    ) -> Result<KeyHandle, CalError> {
        // Validate context is exactly 8 characters
        if context.len() != 8 {
            return Err(CalError::failed_operation(
                "Context must be exactly 8 characters long".to_string(),
                true,
                None,
            ));
        }

        // Determine key length based on cipher
        let key_length = match algorithm.cipher {
            Cipher::AesGcm128 => 16,
            Cipher::AesGcm256 | Cipher::XChaCha20Poly1305 => 32,
            _ => {
                return Err(CalError::failed_operation(
                    "Unsupported cipher for key derivation".to_string(),
                    true,
                    None,
                ))
            }
        };

        // Create derivation info by combining the context string and key_id (as little-endian bytes)
        let mut derivation_info = Vec::with_capacity(16);
        derivation_info.extend_from_slice(context.as_bytes());
        derivation_info.extend_from_slice(&key_id.to_le_bytes());

        // Use Blake2b512 for key derivation - this has a fixed 64-byte output size
        let mut hasher = Blake2b512::new();
        hasher.update(&derivation_info);
        hasher.update(base_key);
        let hash_result = hasher.finalize();

        // Truncate the hash to the desired key length
        let derived_key = hash_result[..key_length].to_vec();

        // Create a key handle with the derived key
        let key_id = nanoid!(10);
        let handle = SoftwareKeyHandle {
            key_id: key_id.clone(),
            spec: algorithm,
            key: derived_key,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn get_random(&self, len: usize) -> Vec<u8> {
        let mut random_bytes = vec![0u8; len];
        let rng = SystemRandom::new();
        rng.fill(&mut random_bytes)
            .expect("Failed to generate random bytes");
        random_bytes
    }

    fn hash(&self, input: &[u8], hash: CryptoHash) -> Result<Vec<u8>, CalError> {
        let result = match hash {
            CryptoHash::Sha2_256 => digest(&SHA256, input).as_ref().to_vec(),
            CryptoHash::Sha2_384 => digest(&SHA384, input).as_ref().to_vec(),
            CryptoHash::Sha2_512 => digest(&SHA512, input).as_ref().to_vec(),
            CryptoHash::Sha2_512_256 => digest(&SHA512_256, input).as_ref().to_vec(),
            CryptoHash::Sha3_224 => Sha3_224::digest(input).to_vec(),
            CryptoHash::Sha3_256 => Sha3_256::digest(input).to_vec(),
            CryptoHash::Sha3_384 => Sha3_384::digest(input).to_vec(),
            CryptoHash::Sha3_512 => Sha3_512::digest(input).to_vec(),
            CryptoHash::Blake2b => {
                let mut hasher = Blake2b512::new();
                hasher.update(input);
                hasher.finalize().to_vec()
            }
            _ => unimplemented!(),
        };

        Ok(result)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SoftwareDHExchange {
    key_id: String,
    private_key_bytes: Vec<u8>,
    public_key_bytes: Vec<u8>,
    storage_manager: Option<StorageManager>,
    spec: KeyPairSpec,
}

impl SoftwareDHExchange {
    /// Creates a new key pair based on the specified algorithm.
    pub fn new(
        key_id: String,
        storage_manager: Option<StorageManager>,
        spec: KeyPairSpec,
    ) -> Result<Self, CalError> {
        match spec.asym_spec {
            AsymmetricKeySpec::Curve25519 => {
                // Generate a new Curve25519 private key using a cryptographically secure RNG
                let private = StaticSecret::random_from_rng(OsRng);
                // Derive the corresponding public key
                let public = X25519PublicKey::from(&private);

                Ok(Self {
                    key_id,
                    private_key_bytes: private.to_bytes().to_vec(),
                    public_key_bytes: public.as_bytes().to_vec(),
                    storage_manager,
                    spec,
                })
            }
            AsymmetricKeySpec::P256 => {
                // Generate a new P-256 private key
                let private = P256SecretKey::random(&mut OsRng);
                // Derive the corresponding public key
                let public = private.public_key();

                Ok(Self {
                    key_id,
                    private_key_bytes: private.to_bytes().to_vec(),
                    public_key_bytes: public.to_sec1_bytes().to_vec(),
                    storage_manager,
                    spec,
                })
            }
            _ => Err(CalError::failed_operation(
                "Unsupported algorithm".to_string(),
                true,
                None,
            )),
        }
    }

    /// Creates a SoftwareDHExchange instance from existing keypair bytes
    pub fn from_keypair_bytes(
        key_id: String,
        private_key: &[u8],
        public_key: &[u8],
        storage_manager: Option<StorageManager>,
        spec: KeyPairSpec,
    ) -> Result<Self, CalError> {
        // Validate that the provided key pair is valid
        match spec.asym_spec {
            AsymmetricKeySpec::Curve25519 => {
                // Verify key lengths
                if private_key.len() != 32 || public_key.len() != 32 {
                    return Err(CalError::failed_operation(
                        "Invalid Curve25519 key length".to_string(),
                        true,
                        None,
                    ));
                }
            }
            AsymmetricKeySpec::P256 => {
                // P-256 private key should be 32 bytes
                if private_key.len() != 32 {
                    return Err(CalError::failed_operation(
                        "Invalid P-256 private key length".to_string(),
                        true,
                        None,
                    ));
                }

                // Public key should be in SEC1 format (uncompressed)
                if public_key.len() < 33
                    || (public_key[0] != 0x04 && public_key[0] != 0x02 && public_key[0] != 0x03)
                {
                    return Err(CalError::failed_operation(
                        "Invalid P-256 public key format".to_string(),
                        true,
                        None,
                    ));
                }
            }
            _ => {
                return Err(CalError::failed_operation(
                    "Unsupported algorithm".to_string(),
                    true,
                    None,
                ));
            }
        }

        // Create the DH Exchange with the provided key material
        Ok(Self {
            key_id,
            private_key_bytes: private_key.to_vec(),
            public_key_bytes: public_key.to_vec(),
            storage_manager,
            spec,
        })
    }

    /// Computes the shared secret between the local private key and a peer's public key.
    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>, CalError> {
        match self.spec.asym_spec {
            AsymmetricKeySpec::Curve25519 => {
                // Convert our private key bytes to a 32-byte array
                let private_key_bytes: [u8; 32] =
                    self.private_key_bytes.as_slice().try_into().map_err(|_| {
                        CalError::failed_operation(
                            "Invalid private key length".to_owned(),
                            true,
                            None,
                        )
                    })?;
                // Create a StaticSecret from the private key bytes
                let private = StaticSecret::from(private_key_bytes);

                // Convert peer public key bytes to a 32-byte array
                let peer_public_bytes: [u8; 32] = peer_public_key.try_into().map_err(|_| {
                    CalError::failed_operation(
                        "Invalid peer public key length".to_owned(),
                        true,
                        None,
                    )
                })?;
                // Create a PublicKey from the peer public key bytes
                let peer_public = X25519PublicKey::from(peer_public_bytes);

                // Perform Diffie-Hellman key exchange
                let shared_secret = private.diffie_hellman(&peer_public);
                Ok(shared_secret.as_bytes().to_vec())
            }
            AsymmetricKeySpec::P256 => {
                // Deserialize our P-256 private key
                let private_key_bytes: [u8; 32] =
                    self.private_key_bytes.as_slice().try_into().map_err(|_| {
                        CalError::failed_operation(
                            "Invalid private key length".to_owned(),
                            true,
                            None,
                        )
                    })?;

                let private =
                    P256SecretKey::from_bytes((&private_key_bytes).into()).map_err(|e| {
                        CalError::failed_operation(
                            "Failed to create P-256 private key".to_owned(),
                            false,
                            Some(anyhow!(e)),
                        )
                    })?;

                // Deserialize the peer's P-256 public key (in SEC1 format)
                let peer_public = P256PublicKey::from_sec1_bytes(peer_public_key).map_err(|e| {
                    CalError::failed_operation(
                        "Invalid P-256 public key format".to_owned(),
                        true,
                        Some(anyhow!(e)),
                    )
                })?;

                // Perform ECDH using the low-level diffie_hellman function
                let shared_secret =
                    diffie_hellman(private.to_nonzero_scalar(), peer_public.as_affine());

                Ok(shared_secret.raw_secret_bytes().to_vec())
            }
            _ => Err(CalError::failed_operation(
                "Unsupported algorithm".to_string(),
                true,
                None,
            )),
        }
    }

    /// Generates session keys from the shared secret, matching libsodium's behavior.
    fn generate_session_keys(
        &self,
        peer_public_key: &[u8],
        is_client: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        // Compute the shared secret first
        let shared_secret = self.compute_shared_secret(peer_public_key)?;

        // Initialize Blake2b hasher (512-bit/64-byte output)
        let mut hasher = Blake2b512::new();

        // Add the shared secret and public keys to the hasher
        hasher.update(&shared_secret);
        if is_client {
            hasher.update(&self.public_key_bytes);
            hasher.update(peer_public_key);
        } else {
            hasher.update(peer_public_key);
            hasher.update(&self.public_key_bytes);
        }

        // Finalize and obtain the 64-byte key material
        let key_material = hasher.finalize();
        let keys = key_material.as_slice();

        // Split into receive (rx) and transmit (tx) keys, consistent with libsodium's implementation
        let (rx, tx) = if is_client {
            (keys[0..32].to_vec(), keys[32..64].to_vec())
        } else {
            (keys[32..64].to_vec(), keys[0..32].to_vec())
        };

        Ok((rx, tx))
    }

    // Create a key handle from derived key material
    fn create_key_handle(
        &self,
        key_material: Vec<u8>,
        key_id_suffix: &str,
    ) -> Result<KeyHandle, CalError> {
        // Generate a unique key ID
        let key_id = format!("{}_{}", self.key_id, key_id_suffix);

        let cipher = self.spec.cipher.ok_or_else(
            || {
                error!("derive_client_key_handles and derive_server_key_handles need a KeyPairSpec supplied which cipher is not None.");
                CalError::bad_parameter(
                    "derive_client_key_handles and derive_server_key_handles need a KeyPairSpec supplied which cipher is not None.".to_owned(), 
                    true,
                    None
                )}
        )?;

        // Create a SoftwareKeyHandle with the derived key
        let handle = SoftwareKeyHandle {
            key_id,
            key: key_material,
            storage_manager: self.storage_manager.clone(),
            spec: KeySpec {
                cipher,
                ephemeral: self.spec.ephemeral,
                signing_hash: self.spec.signing_hash,
                non_exportable: self.spec.non_exportable,
            },
        };

        // Convert to KeyHandle
        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }
}

impl DHKeyExchangeImpl for SoftwareDHExchange {
    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    /// Returns the public key as bytes for sharing with the peer
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key_bytes.clone())
    }

    fn derive_client_session_keys(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        // Client mode: is_client = true
        self.generate_session_keys(server_pk, true)
    }

    fn derive_server_session_keys(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        // Server mode: is_client = false
        self.generate_session_keys(client_pk, false)
    }

    /// Derives client session keys and returns them as key handles
    fn derive_client_key_handles(
        &mut self,
        server_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        let (rx_key, tx_key) = self.generate_session_keys(server_pk, true)?;

        // Create key handles for the derived keys
        let rx_handle = self.create_key_handle(rx_key, "rx")?;
        let tx_handle = self.create_key_handle(tx_key, "tx")?;

        Ok((rx_handle, tx_handle))
    }

    /// Derives server session keys and returns them as key handles
    fn derive_server_key_handles(
        &mut self,
        client_pk: &[u8],
    ) -> Result<(KeyHandle, KeyHandle), CalError> {
        let (rx_key, tx_key) = self.generate_session_keys(client_pk, false)?;

        // Create key handles for the derived keys
        let rx_handle = self.create_key_handle(rx_key, "rx")?;
        let tx_handle = self.create_key_handle(tx_key, "tx")?;

        Ok((rx_handle, tx_handle))
    }
}

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
    prelude::KDF,
    storage::KeyData,
};
use argon2::{
    password_hash::SaltString, Argon2, Params, PasswordHasher, MAX_SALT_LEN, MIN_SALT_LEN,
};
use blake2::{Blake2b512, Digest};
use nanoid::nanoid;
use ring::{
    aead::Algorithm,
    agreement::{self, EphemeralPrivateKey, PublicKey, UnparsedPublicKey},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair},
};

impl ProviderImpl for SoftwareProvider {
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot create non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id = nanoid!(10);

        // Initialize the system random generator
        let rng = SystemRandom::new();

        let algo: &Algorithm = spec.cipher.into();

        // Generate the symmetric key data
        let mut key_data = vec![0u8; algo.key_len()];
        rng.fill(&mut key_data)
            .expect("Failed to generate symmetric key");

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

        // Initialize SoftwareKeyHandle with the LessSafeKey
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
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot load keys".to_owned(),
                true,
                None,
            ));
        }

        let storage_data = self.storage_manager.as_ref().unwrap().get(key_id.clone())?;

        let Spec::KeySpec(spec) = storage_data.spec else {
            return Err(CalError::failed_operation(
                "Trying to load KeyPair as symmetric Key".to_owned(),
                true,
                None,
            ));
        };

        let Some(key_data) = storage_data.secret_data else {
            return Err(CalError::failed_operation(
                "no sensitive data for key found".to_owned(),
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
        if self.storage_manager.is_none() && !spec.ephemeral {
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
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot load keys".to_owned(),
                true,
                None,
            ));
        }

        let storage_data = self.storage_manager.as_ref().unwrap().get(key_id.clone())?;

        let Spec::KeyPairSpec(spec) = storage_data.spec else {
            return Err(CalError::failed_operation(
                "Trying to load symmetric Key as KeyPair".to_owned(),
                true,
                None,
            ));
        };

        let key_data = storage_data.secret_data;

        let Some(public_key) = storage_data.public_data else {
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
        let dh_exchange =
            SoftwareDHExchange::new(key_id, self.storage_manager.clone(), spec).unwrap();

        // Wrap in DHExchange and return
        Ok(DHExchange {
            implementation: dh_exchange.into(),
        })
    }

    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        if self.storage_manager.is_none() {
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot have stored keys".to_owned(),
                true,
                None,
            ));
        }
        Ok(self.storage_manager.as_ref().unwrap().get_all_keys())
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
            .map_err(|_| CalError::failed_operation("Failed to encode salt".into(), true, None))?;

        // Perform password hashing with specified parameters
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_str)
            .map_err(|e| CalError::failed_operation(e.to_string(), false, None))?;

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
}

#[derive(Debug)]
pub(crate) struct SoftwareDHExchange {
    key_id: String,
    private_key: Option<EphemeralPrivateKey>,
    public_key: PublicKey,
    storage_manager: Option<StorageManager>,
    spec: KeyPairSpec,
}

impl SoftwareDHExchange {
    pub fn new(
        key_id: String,
        storage_manager: Option<StorageManager>,
        spec: KeyPairSpec,
    ) -> Result<Self, CalError> {
        let rng = SystemRandom::new();

        // Generate an ephemeral private key for DH using X25519
        let private_key = EphemeralPrivateKey::generate(spec.asym_spec.try_into()?, &rng)
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
            spec,
        })
    }

    // Compute shared secret using the given peer public key
    fn compute_shared_secret(&mut self, peer_public_key_bytes: &[u8]) -> Result<Vec<u8>, CalError> {
        let algo: &'static agreement::Algorithm = match self.spec.asym_spec {
            AsymmetricKeySpec::P256 => &agreement::ECDH_P256,
            AsymmetricKeySpec::P384 => &agreement::ECDH_P384,
            AsymmetricKeySpec::Curve25519 => &agreement::X25519,
            _ => {
                return Err(CalError::failed_operation(
                    "Algorithm not supported".to_string(),
                    true,
                    None,
                ))
            }
        };

        let peer_public_key = UnparsedPublicKey::new(algo, peer_public_key_bytes);

        if self.private_key.is_none() {
            return Err(CalError::failed_operation(
                "No private key available".to_string(),
                true,
                None,
            ));
        }

        // Take ownership of the private key (consumes it)
        let private_key = self.private_key.take().unwrap();

        // Perform key agreement to produce the shared secret
        agreement::agree_ephemeral(private_key, &peer_public_key, |shared_secret| {
            Ok(shared_secret.to_vec())
        })
        .map_err(|err| CalError::failed_operation(err.to_string(), true, None))?
    }

    // Generate session keys in the libsodium format
    fn generate_session_keys(
        &mut self,
        peer_public_key: &[u8],
        is_client: bool,
    ) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        // Compute the shared secret
        let shared_secret = self.compute_shared_secret(peer_public_key)?;

        // Create a context for key derivation that mirrors libsodium's generichash
        let self_pk = self.public_key.as_ref().to_vec();

        // Create a BLAKE2b hash context (similar to libsodium's generichash)
        // We need to hash: shared_secret | client_pk | server_pk
        let mut params = blake2b_simd::Params::new();
        params.hash_length(64); // Generate 64 bytes (for two 32-byte keys)
        let mut state = params.to_state();

        // Add the shared secret to the hash
        state.update(&shared_secret);

        // Add the public keys in the order that libsodium does:
        // For both client and server, the order is: client_pk | server_pk
        if is_client {
            state.update(&self_pk); // client_pk (self)
            state.update(peer_public_key); // server_pk (peer)
        } else {
            state.update(peer_public_key); // client_pk (peer)
            state.update(&self_pk); // server_pk (self)
        }

        // Finalize the hash to get the session keys
        let keys = state.finalize().as_bytes().to_vec();

        // In libsodium:
        // - Client: rx = first half, tx = second half
        // - Server: rx = second half, tx = first half
        let (rx, tx) = if is_client {
            // Client mode
            let rx = keys[0..32].to_vec();
            let tx = keys[32..64].to_vec();
            (rx, tx)
        } else {
            // Server mode
            let rx = keys[32..64].to_vec();
            let tx = keys[0..32].to_vec();
            (rx, tx)
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
            || CalError::bad_parameter(
                "derive_client_key_handles and derive_server_key_handles need a KeyPairSpec supplied which cipher is not None.".to_owned(), 
            true, 
            None
        ))?;

        // Create a SoftwareKeyHandle with the derived key
        let handle = SoftwareKeyHandle {
            key_id,
            key: key_material,
            storage_manager: self.storage_manager.clone(),
            spec: KeySpec {
                cipher,
                ephemeral: self.spec.ephemeral,
                signing_hash: self.spec.signing_hash,
            },
        };

        // Convert to KeyHandle
        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }
}

impl DHKeyExchangeImpl for SoftwareDHExchange {
    /// Returns the public key as bytes for sharing with the peer
    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.as_ref().to_vec())
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
        let (rx_key, tx_key) = self.derive_client_session_keys(server_pk)?;

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
        let (rx_key, tx_key) = self.derive_server_session_keys(client_pk)?;

        // Create key handles for the derived keys
        let rx_handle = self.create_key_handle(rx_key, "rx")?;
        let tx_handle = self.create_key_handle(tx_key, "tx")?;

        Ok((rx_handle, tx_handle))
    }
}

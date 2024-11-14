use std::sync::Arc;

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
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};

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
        // Simulate loading a key from storage
        let key_data = vec![0u8; 32]; // Placeholder for stored 256-bit AES key

        // Initialize SoftwareKeyHandle with the raw key data
        let handle = SoftwareKeyHandle::new(key_id, None, key_data)?;

        Ok(KeyHandle {
            implementation: handle.into(),
        })
    }

    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        let key_id = nanoid!(10);

        // Generate ECC key pair using ring's SystemRandom for asymmetric keys
        let rng = SystemRandom::new();
        let algorithm = spec.asym_spec.into();

        let pkcs8_bytes =
            EcdsaKeyPair::generate_pkcs8(algorithm, &rng).expect("Failed to generate private key");

        // Create an EcdsaKeyPair from the PKCS#8-encoded private key
        let key_pair = EcdsaKeyPair::from_pkcs8(algorithm, pkcs8_bytes.as_ref(), &rng)
            .expect("Failed to parse key pair");

        self.save_key_pair_metadata(key_id.clone(), SerializableSpec::KeyPairSpec(spec))
            .unwrap();

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
        // Simulate loading key data from storage
        let private_key = vec![0u8; 32]; // Placeholder for stored private key
        let public_key = vec![0u8; 32]; // Placeholder for stored public key

        // Initialize SoftwareKeyPairHandle with loaded private and public key bytes
        let handle =
            SoftwareKeyPairHandle::new(key_id, KeyPairSpec::default(), private_key, public_key)?;

        Ok(KeyPairHandle {
            implementation: handle.into(),
        })
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

    fn get_capabilities(&self) -> ProviderConfig {
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

        // Perform key agreement to produce an intermediate shared secret
        agreement::agree_ephemeral(
            self.private_key.take().unwrap(),
            &peer_public_key,
            |shared_secret| Ok(shared_secret.to_vec()),
        )
        .expect("Failed to compute intermediate DH secret")
    }

    /// Computes the final shared secret, derives a symmetric key, and returns it as a key handle
    fn add_external_final(&mut self, external_key: &[u8]) -> Result<KeyHandleImplEnum, CalError> {
        // Parse the final external public key
        let peer_public_key = UnparsedPublicKey::new(&X25519, external_key);

        // Perform key agreement to produce the final shared secret
        let shared_secret = agreement::agree_ephemeral(
            self.private_key.take().unwrap(),
            &peer_public_key,
            |shared_secret| shared_secret.to_vec(),
        )
        .expect("Failed to compute final DH secret");

        // Derive a symmetric key (AES-256) from the shared secret
        let key_material = &shared_secret[0..32]; // Use the first 32 bytes as AES-256 key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key_material)
            .expect("Failed to create AES key from shared secret");
        let symmetric_key = Arc::new(LessSafeKey::new(unbound_key));

        // Return the symmetric key wrapped in KeyHandleImplEnum
        Ok(KeyHandleImplEnum::SoftwareKeyHandle(SoftwareKeyHandle {
            key_id: self.key_id.clone(),
            key: symmetric_key,
        }))
    }
}

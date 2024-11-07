use crate::common::{
    config::{KeyPairSpec, KeySpec},
    error::CalError,
    traits::key_handle::{KeyHandleImpl, KeyPairHandleImpl},
    DHExchange,
};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, Signature, UnparsedPublicKey},
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyHandle {
    pub(crate) key_id: String,
    pub(crate) key: Arc<LessSafeKey>,
}

#[derive(Debug, Clone)]
pub(crate) struct SoftwareKeyPairHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeyPairSpec,
    pub(crate) signing_key: Option<Arc<EcdsaKeyPair>>,
    pub(crate) public_key: Vec<u8>,
}

impl SoftwareKeyHandle {
    pub fn new(key_id: String, spec: Option<KeySpec>, key_data: Vec<u8>) -> Result<Self, CalError> {
        // Create the AES key for encryption and decryption
        let unbound_key = UnboundKey::new(spec.as_ref().unwrap().cipher.into(), &key_data)
            .expect("Failed to create AES key");
        let key = Arc::new(LessSafeKey::new(unbound_key));

        Ok(Self { key_id, key })
    }
}

impl KeyHandleImpl for SoftwareKeyHandle {
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        let rng = SystemRandom::new();

        // Generate a unique nonce for this encryption operation
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes)
            .expect("Failed to generate nonce");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Prepare additional associated data (AAD), here as an empty slice
        let aad = Aad::empty();

        // Copy the plaintext data and prepare for encryption
        let mut in_out = data.to_vec();
        in_out.extend(vec![0u8; 16]); // Reserve space for the authentication tag

        // Perform encryption
        self.key
            .seal_in_place_append_tag(nonce, aad, &mut in_out)
            .expect("Encryption failed");

        // Prepend the nonce to the ciphertext
        let mut encrypted_data = nonce_bytes.to_vec();
        encrypted_data.extend(&in_out);

        Ok(encrypted_data)
    }

    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        // Separate nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

        // Prepare AAD as an empty slice
        let aad = Aad::empty();

        // Copy the ciphertext for in-place decryption
        let mut in_out = ciphertext.to_vec();

        // Perform decryption
        self.key
            .open_in_place(nonce, aad, &mut in_out)
            .expect("Decryption failed");

        // Remove the authentication tag
        in_out.truncate(in_out.len() - 16);
        Ok(in_out)
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        todo!("Cannot extract symmetric keys")
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key."]
    fn delete(self) -> Result<(), CalError> {
        todo!()
    }
}

impl SoftwareKeyPairHandle {
    pub fn new(
        key_id: String,
        spec: KeyPairSpec,
        private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<Self, CalError> {
        let rng = SystemRandom::new();

        // Create the signing key using both private and public key
        let signing_key = Arc::new(
            EcdsaKeyPair::from_private_key_and_public_key(
                spec.asym_spec.into(),
                &private_key,
                &public_key,
                &rng,
            )
            .expect("Failed to create key pair"),
        );

        Ok(Self {
            key_id,
            spec,
            signing_key: Some(signing_key.clone()),
            public_key,
        })
    }

    pub fn new_public_only(
        key_id: String,
        spec: KeyPairSpec,
        public_key: Vec<u8>,
    ) -> Result<Self, CalError> {
        Ok(Self {
            key_id,
            spec,
            signing_key: None,
            public_key,
        })
    }
}

impl KeyHandleImpl for SoftwareKeyPairHandle {
    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Encryption not supported for ECC keys")
    }

    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Decryption not supported for ECC keys")
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.clone())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key."]
    fn delete(self) -> Result<(), CalError> {
        todo!()
    }
}

impl KeyPairHandleImpl for SoftwareKeyPairHandle {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        let signing_key = self
            .signing_key
            .as_ref()
            .expect("No private key available for signing");

        // Secure random generator for signing
        let rng = SystemRandom::new();

        // Sign the data
        let signature: Signature = signing_key.sign(&rng, data).expect("Signing failed");

        Ok(signature.as_ref().to_vec())
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, CalError> {
        // Create an UnparsedPublicKey using the algorithm and the public key bytes
        let public_key = UnparsedPublicKey::new(self.spec.asym_spec.into(), &self.public_key);

        // Verify the signature with the provided data and signature
        match public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn encrypt_data(&self, _data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Encryption not supported for ECC keys")
    }

    fn decrypt_data(&self, _encrypted_data: &[u8]) -> Result<Vec<u8>, CalError> {
        todo!("Decryption not supported for ECC keys")
    }

    fn get_public_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.clone())
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Ok(self.public_key.clone())
    }

    fn start_dh_exchange(&self) -> Result<DHExchange, CalError> {
        todo!("DH exchange not supported")
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    #[doc = " Delete this key pair."]
    fn delete(self) -> Result<(), CalError> {
        todo!()
    }
}

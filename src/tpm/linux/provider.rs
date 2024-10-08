use super::TpmProvider;
use crate::{
    common::{
        crypto::{algorithms::encryption::AsymmetricEncryption, KeyUsage},
        error::SecurityModuleError,
        traits::{module_provider::Provider, module_provider_config::ProviderConfig},
    },
    tpm::TpmConfig,
};
use async_std::sync::Mutex;
use async_trait::async_trait;
use std::{str::FromStr, sync::Arc};
use tracing::instrument;
use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{KeyHandle as TssKeyHandle, PersistentTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, SymmetricMode},
        dynamic_handles::Persistent,
        key_bits::AesKeyBits,
        resource_handles::{Hierarchy, Provision},
    },
    structures::{
        Digest, EccPoint, HashScheme, KeyDerivationFunctionScheme, Private, Public, PublicBuilder,
        PublicEccParameters, PublicKeyRsa, PublicRsaParameters, RsaExponent, RsaScheme,
        SymmetricDefinition,
    },
    Context, TctiNameConf,
};

/// Implements the `Provider` trait, providing cryptographic operations utilizing a TPM.
#[async_trait]
impl Provider for TpmProvider {
    /// Creates a new cryptographic key identified by `key_id`.
    ///
    /// This method generates a new cryptographic key within the TPM, using the specified
    /// algorithm, symmetric algorithm, hash algorithm, and key usages. The key is made persistent
    /// and associated with the provided `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be created.
    /// * `key_algorithm` - The asymmetric encryption algorithm to be used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm to be used with the key.
    /// * `hash` - An optional hash algorithm to be used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was created successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    async fn create_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        let config = config.as_any().await.downcast_ref::<TpmConfig>().unwrap();

        self.key_algorithm = config.key_algorithm;
        self.sym_algorithm = config.sym_algorithm;
        self.hash = config.hash;
        self.key_usages = config.key_usages.clone();

        let primary_pub = match self.key_algorithm.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(key_bits) => PublicBuilder::new()
                .with_public_algorithm((*self.key_algorithm.as_ref().unwrap()).into())
                .with_name_hashing_algorithm((*self.hash.as_ref().unwrap()).into())
                .with_rsa_parameters(PublicRsaParameters::new(
                    self.sym_algorithm.unwrap().into(),
                    RsaScheme::Null,
                    (*key_bits).into(),
                    RsaExponent::default(),
                ))
                .with_rsa_unique_identifier(PublicKeyRsa::default()),
            AsymmetricEncryption::Ecc(ecc_scheme) => PublicBuilder::new()
                .with_public_algorithm((*self.key_algorithm.as_ref().unwrap()).into())
                .with_name_hashing_algorithm((*self.hash.as_ref().unwrap()).into())
                .with_ecc_parameters(PublicEccParameters::new(
                    self.sym_algorithm.unwrap().into(),
                    (*ecc_scheme).into(),
                    self.key_algorithm
                        .as_ref()
                        .unwrap()
                        .ecc_curve()
                        .unwrap()
                        .into(),
                    KeyDerivationFunctionScheme::Kdf2(HashScheme::new(
                        (*self.hash.as_ref().unwrap()).into(),
                    )),
                ))
                .with_ecc_unique_identifier(EccPoint::default()),
        };

        let primary_pub = primary_pub
            .with_object_attributes(
                // Private Key attributes
                ObjectAttributesBuilder::new()
                    // Indicate the key can only exist within this tpm and can not be exported.
                    .with_fixed_tpm(true)
                    // The primary key and it's descendent keys can't be moved to other primary
                    // keys.
                    .with_fixed_parent(true)
                    // The primary key will persist over suspend and resume of the system.
                    .with_st_clear(true)
                    // The primary key was generated entirely inside the TPM - only this TPM
                    // knows it's content.
                    .with_sensitive_data_origin(true)
                    // This key requires "authentication" to the TPM to access - this can be
                    // an HMAC or password session. HMAC sessions are used by default with
                    // the "execute_with_nullauth_session" function.
                    .with_user_with_auth(
                        self.key_usages
                            .as_ref()
                            .unwrap()
                            .contains(&KeyUsage::ClientAuth),
                    )
                    // This key has the ability to decrypt
                    .with_decrypt(
                        self.key_usages
                            .as_ref()
                            .unwrap()
                            .contains(&KeyUsage::Decrypt),
                    )
                    // This key has the ability to sign
                    .with_sign_encrypt(
                        self.key_usages
                            .as_ref()
                            .unwrap()
                            .contains(&KeyUsage::SignEncrypt),
                    )
                    // Create self-signed certificates
                    .with_x509_sign(
                        self.key_usages
                            .as_ref()
                            .unwrap()
                            .contains(&KeyUsage::CreateX509),
                    )
                    // This key may only be used to encrypt or sign objects that are within
                    // the TPM - it can not encrypt or sign external data.
                    .with_restricted(false)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let key_handle = self
            .provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
            .unwrap();

        let persistent_handle =
            Persistent::Persistent(PersistentTpmHandle::new(key_handle.key_handle.into()).unwrap());

        self.key_handle = Some(Arc::new(Mutex::new(key_handle.key_handle)));

        self.key_id = key_handle.key_handle.value().to_string();
        self.provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .evict_control(
                Provision::Owner, // TPM owner authorization
                (*self.key_handle.as_ref().unwrap().lock().await).into(),
                persistent_handle, // Chosen persistent handle
            )
            .expect("Failed to make key persistent");

        self.key_id = key_id.to_string();

        Ok(())
    }

    /// Loads an existing cryptographic key identified by `key_id`.
    ///
    /// This method loads an existing cryptographic key from the TPM, using the specified
    /// algorithm, symmetric algorithm, hash algorithm, and key usages. The loaded key is
    /// associated with the provided `key_id`.
    ///
    /// # Arguments
    ///
    /// * `key_id` - A string slice that uniquely identifies the key to be loaded.
    /// * `key_algorithm` - The asymmetric encryption algorithm used for the key.
    /// * `sym_algorithm` - An optional symmetric encryption algorithm used with the key.
    /// * `hash` - An optional hash algorithm used with the key.
    /// * `key_usages` - A vector of `AppKeyUsage` values specifying the intended usages for the key.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the key was loaded successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    async fn load_key(
        &mut self,
        key_id: &str,
        config: Box<dyn ProviderConfig>,
    ) -> Result<(), SecurityModuleError> {
        let config = config.as_any().await.downcast_ref::<TpmConfig>().unwrap();

        self.key_algorithm = config.key_algorithm;
        self.sym_algorithm = config.sym_algorithm;
        self.hash = config.hash;
        self.key_usages = config.key_usages.clone();

        // Start an authorization session
        let session = self
            .provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::Aes {
                    key_bits: AesKeyBits::Aes256,
                    mode: SymmetricMode::Cbc,
                },
                HashingAlgorithm::Sha512,
            )
            .unwrap();
        let session_attr = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .with_continue_session(true)
            .build();

        self.provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .tr_sess_set_attributes(session.unwrap(), session_attr.0, session_attr.1)
            .unwrap();

        let primary_pub = match self.key_algorithm.as_ref().unwrap() {
            AsymmetricEncryption::Rsa(_) => todo!(),
            AsymmetricEncryption::Ecc(ecc_scheme) => PublicEccParameters::new(
                self.sym_algorithm.unwrap().into(),
                (*ecc_scheme).into(),
                self.key_algorithm
                    .as_ref()
                    .unwrap()
                    .ecc_curve()
                    .unwrap()
                    .into(),
                KeyDerivationFunctionScheme::Kdf2(HashScheme::new(self.hash.unwrap().into())),
            ),
        };

        let obj_attributes = ObjectAttributesBuilder::new()
            // Indicate the key can only exist within this tpm and can not be exported.
            .with_fixed_tpm(true)
            // The primary key and it's descendent keys can't be moved to other primary
            // keys.
            .with_fixed_parent(true)
            // The primary key will persist over suspend and resume of the system.
            .with_st_clear(true)
            // The primary key was generated entirely inside the TPM - only this TPM
            // knows it's content.
            .with_sensitive_data_origin(true)
            // This key requires "authentication" to the TPM to access - this can be
            // an HMAC or password session. HMAC sessions are used by default with
            // the "execute_with_nullauth_session" function.
            .with_user_with_auth(
                self.key_usages
                    .as_ref()
                    .unwrap()
                    .contains(&KeyUsage::ClientAuth),
            )
            // This key has the ability to decrypt
            .with_decrypt(
                self.key_usages
                    .as_ref()
                    .unwrap()
                    .contains(&KeyUsage::Decrypt),
            )
            // This key has the ability to sign
            .with_sign_encrypt(
                self.key_usages
                    .as_ref()
                    .unwrap()
                    .contains(&KeyUsage::SignEncrypt),
            )
            // Create self-signed certificates
            .with_x509_sign(
                self.key_usages
                    .as_ref()
                    .unwrap()
                    .contains(&KeyUsage::CreateX509),
            )
            // This key may only be used to encrypt or sign objects that are within
            // the TPM - it can not encrypt or sign external data.
            .with_restricted(false)
            .build()
            .unwrap();

        let private = Private::default();
        let public = Public::Ecc {
            object_attributes: obj_attributes,
            name_hashing_algorithm: self.hash.unwrap().into(),
            auth_policy: Digest::default(),
            parameters: primary_pub,
            unique: EccPoint::default(),
        };

        let key_handle = self
            .provider_handle
            .as_ref()
            .unwrap()
            .lock()
            .await
            .load(TssKeyHandle::Null, private, public)
            .unwrap();

        self.key_handle = Some(Arc::new(Mutex::new(key_handle)));
        self.key_id = key_id.to_string();

        Ok(())
    }

    /// Initializes the TPM module and returns a handle for further operations.
    ///
    /// This method initializes the TPM context and prepares it for use. It should be called
    /// before performing any other operations with the TPM.
    ///
    /// # Returns
    ///
    /// A `Result` that, on success, contains `Ok(())`, indicating that the module was initialized successfully.
    /// On failure, it returns a `SecurityModuleError`.
    #[instrument]
    async fn initialize_module(&mut self) -> Result<(), SecurityModuleError> {
        // let tcti = TctiNameConf::from_environment_variable().unwrap();
        let tcti = TctiNameConf::from_str("device:/dev/tpm0").unwrap();

        let context = Context::new(tcti)
            .map_err(|e| SecurityModuleError::InitializationError(e.to_string()))?;

        self.provider_handle = Some(Arc::new(Mutex::new(context)));

        Ok(())
    }
}

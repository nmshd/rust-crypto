use super::{
    asymmetric_spec_to_pcwstr, cipher_to_pcwstr, crypto_hash_to_pcwstr, execute_ncrypt_function,
    get_asymmetric_key_length_bits, get_symmetric_key_length_bytes,
    key_handle::{NcryptKeyHandleWrapper, WindowsKeyHandle, WindowsKeyPairHandle},
    WindowsProvider, WindowsProviderFactory,
};
use crate::{
    common::{
        config::{KeyPairSpec, KeySpec, ProviderConfig, Spec},
        crypto::algorithms::key_derivation::KDF,
        error::CalError,
        traits::module_provider::{ProviderFactory, ProviderImpl},
        KeyHandle, KeyPairHandle,
    },
    prelude::CryptoHash,
    storage::KeyData,
};
use anyhow::anyhow;
use itertools::Itertools;
use std::mem;
use tracing::{error, instrument};
use windows::{
    core::{HSTRING, PCWSTR},
    Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
        BCryptGenRandom, BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider,
        NCryptCreatePersistedKey, NCryptFinalizeKey, NCryptImportKey, NCryptOpenKey,
        NCryptSetProperty, BCRYPT_ALG_HANDLE, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB,
        BCRYPT_HASH_HANDLE, BCRYPT_HASH_LENGTH, BCRYPT_KEY_DATA_BLOB, BCRYPT_KEY_DATA_BLOB_HEADER,
        BCRYPT_OBJECT_LENGTH, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_RSAPRIVATE_BLOB,
        BCRYPT_RSAPUBLIC_BLOB, BCRYPT_USE_SYSTEM_PREFERRED_RNG, CERT_KEY_SPEC,
        NCRYPT_ALGORITHM_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
        NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS,
        NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY, NCRYPT_NAME_PROPERTY,
        NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_SILENT_FLAG,
    },
};

impl ProviderImpl for WindowsProvider {
    #[instrument(skip(self, spec), err)]
    fn create_key(&mut self, spec: KeySpec) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot create non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot create non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id_str = nanoid::nanoid!(10);
        let key_id_hstring = HSTRING::from(key_id_str.as_str());

        let mut h_key = Default::default();
        let alg_id_pcwstr = cipher_to_pcwstr(spec.cipher)?;

        let dw_flags = if spec.ephemeral {
            0 // Ephemeral keys are not persisted
        } else {
            NCRYPT_OVERWRITE_KEY_FLAG.0 // Persisted keys can be overwritten
        };

        execute_ncrypt_function!(@result NCryptCreatePersistedKey(
            self.provider_handle.0,
            &mut h_key,
            alg_id_pcwstr,
            if spec.ephemeral { PCWSTR::null() } else { PCWSTR(key_id_hstring.as_ptr()) },
            CERT_KEY_SPEC(0), // dwLegacyKeySpec
            NCRYPT_FLAGS(dw_flags),
        ))?;

        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        // Set key length
        let key_len_bits = (get_symmetric_key_length_bytes(spec.cipher)? * 8) as u32;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_LENGTH_PROPERTY,
            &key_len_bits.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Set key usage (allowing decryption for symmetric keys)
        // NCRYPT_ALLOW_DECRYPT_FLAG permits use with NCryptDecrypt.
        let key_usage_flags_val = NCRYPT_ALLOW_DECRYPT_FLAG;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage_flags_val.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Allow plaintext export for HMAC (if key is exportable, which it is by default for symmetric)
        // This might be restricted by machine policy.
        let export_policy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &export_policy.to_le_bytes(),
            NCRYPT_SILENT_FLAG
        ))?;

        execute_ncrypt_function!(@result NCryptFinalizeKey(key_handle_wrapper.0, NCRYPT_SILENT_FLAG))?;

        if !spec.ephemeral {
            if let Some(sm) = &self.storage_manager {
                let key_data_to_store = KeyData {
                    id: key_id_str.clone(),
                    secret_data: None, // Key material is in TPM
                    public_data: None,
                    additional_data: None,
                    spec: Spec::KeySpec(spec),
                };
                sm.store(key_id_str.clone(), key_data_to_store)?;
            }
        }

        let windows_key_handle = WindowsKeyHandle {
            key_id: key_id_str,
            key_handle: key_handle_wrapper,
            spec,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyHandle {
            implementation: windows_key_handle.into(),
        })
    }

    #[instrument(skip(self), err)]
    fn load_key(&mut self, key_id: String) -> Result<KeyHandle, CalError> {
        let storage_manager = self.storage_manager.as_ref().ok_or_else(|| {
            error!("Cannot load keys without a storage manager (non-ephemeral provider).");
            CalError::failed_operation(
                "Ephemeral provider cannot load keys.".to_string(),
                true,
                None,
            )
        })?;

        let stored_data = storage_manager.get(key_id.clone())?;
        let spec = match stored_data.spec {
            Spec::KeySpec(s) => s,
            _ => {
                return Err(CalError::bad_parameter(
                    "Attempted to load a non-symmetric key as a symmetric key.".to_string(),
                    true,
                    None,
                ))
            }
        };

        if spec.ephemeral {
            return Err(CalError::ephemeral_key_required()); // Should not happen if stored
        }

        let mut h_key = Default::default();
        let key_id_hstring = HSTRING::from(key_id.as_str());

        execute_ncrypt_function!(@result NCryptOpenKey(
            self.provider_handle.0,
            &mut h_key,
            PCWSTR(key_id_hstring.as_ptr()),
            CERT_KEY_SPEC(0), // dwLegacyKeySpec
            NCRYPT_SILENT_FLAG,
        ))?;

        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        let windows_key_handle = WindowsKeyHandle {
            key_id,
            key_handle: key_handle_wrapper,
            spec,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyHandle {
            implementation: windows_key_handle.into(),
        })
    }

    #[instrument(skip(self, spec, data), err)]
    fn import_key(&mut self, spec: KeySpec, data: &[u8]) -> Result<KeyHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            error!("This is an ephemeral provider, it cannot import non-ephemeral keys");
            return Err(CalError::failed_operation(
                "This is an ephemeral provider, it cannot import non-ephemeral keys".to_owned(),
                true,
                None,
            ));
        }

        let key_id_str = nanoid::nanoid!(10);
        // key_id_hstring will be used for NCRYPT_NAME_PROPERTY if not ephemeral
        let key_id_hstring = HSTRING::from(key_id_str.as_str());
        // alg_id_pcwstr will be used for NCRYPT_ALGORITHM_PROPERTY
        let alg_id_pcwstr = cipher_to_pcwstr(spec.cipher)?;

        let blob_header = BCRYPT_KEY_DATA_BLOB_HEADER {
            dwMagic: windows::Win32::Security::Cryptography::BCRYPT_KEY_DATA_BLOB_MAGIC,
            dwVersion: windows::Win32::Security::Cryptography::BCRYPT_KEY_DATA_BLOB_VERSION1,
            cbKeyData: data.len() as u32,
        };
        let mut key_blob_vec = Vec::with_capacity(mem::size_of_val(&blob_header) + data.len());
        key_blob_vec.extend_from_slice(unsafe {
            std::slice::from_raw_parts(
                &blob_header as *const _ as *const u8,
                mem::size_of_val(&blob_header),
            )
        });
        key_blob_vec.extend_from_slice(data);

        let mut h_key = Default::default();
        let dw_import_flags_val = if spec.ephemeral {
            0 // For ephemeral keys, no special flags beyond default. Key is not named.
        } else {
            // For persisted keys, NCRYPT_OVERWRITE_KEY_FLAG might be relevant if the (unnamed) import
            // could conflict, though naming happens via NCryptSetProperty.
            // Let's assume for now that import creates a new unnamed object, then we name it.
            0
        };
        let dw_import_flags = NCRYPT_FLAGS(dw_import_flags_val);

        execute_ncrypt_function!(@result NCryptImportKey(
            self.provider_handle.0,
            None,
            BCRYPT_KEY_DATA_BLOB,
            None,
            &mut h_key,
            &key_blob_vec,
            dw_import_flags, // dwFlags for NCryptImportKey
        ))?;
        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        // --- Set properties for the imported key ---

        // Set NCRYPT_ALGORITHM_PROPERTY (Crucial)
        let alg_id_utf16: Vec<u16> = unsafe { alg_id_pcwstr.as_wide() }.into();
        let alg_id_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(alg_id_utf16.as_ptr() as *const u8, alg_id_utf16.len() * 2)
        };
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_ALGORITHM_PROPERTY,
            alg_id_bytes,
            NCRYPT_SILENT_FLAG,
        ))?;

        // Set NCRYPT_NAME_PROPERTY if not ephemeral
        if !spec.ephemeral {
            let name_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    key_id_hstring.as_ptr() as *const u8,
                    key_id_hstring.len() * 2,
                )
            };
            execute_ncrypt_function!(@result NCryptSetProperty(
                key_handle_wrapper.0.into(),
                NCRYPT_NAME_PROPERTY,
                name_bytes,
                NCRYPT_OVERWRITE_KEY_FLAG,
            ))?;
        }

        // Set NCRYPT_LENGTH_PROPERTY
        let key_len_bits = (get_symmetric_key_length_bytes(spec.cipher)? * 8) as u32;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_LENGTH_PROPERTY,
            &key_len_bits.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Set NCRYPT_KEY_USAGE_PROPERTY
        let key_usage_flags_val = NCRYPT_ALLOW_DECRYPT_FLAG;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage_flags_val.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Set NCRYPT_EXPORT_POLICY_PROPERTY
        let export_policy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &export_policy.to_le_bytes(),
            NCRYPT_SILENT_FLAG
        ))?;

        // --- Finalize the key ---
        execute_ncrypt_function!(@result NCryptFinalizeKey(key_handle_wrapper.0, NCRYPT_SILENT_FLAG))?;

        if !spec.ephemeral {
            if let Some(sm) = &self.storage_manager {
                let key_data_to_store = KeyData {
                    id: key_id_str.clone(),
                    secret_data: None,
                    public_data: None,
                    additional_data: None,
                    spec: Spec::KeySpec(spec),
                };
                sm.store(key_id_str.clone(), key_data_to_store)?;
            }
        }

        let windows_key_handle = WindowsKeyHandle {
            key_id: key_id_str,
            key_handle: key_handle_wrapper,
            spec,
            storage_manager: self.storage_manager.clone(),
        };
        Ok(KeyHandle {
            implementation: windows_key_handle.into(),
        })
    }

    #[instrument(skip(self, spec), err)]
    fn create_key_pair(&mut self, spec: KeyPairSpec) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::failed_operation(
                "Ephemeral provider cannot create non-ephemeral key pairs.".to_owned(),
                true,
                None,
            ));
        }

        let key_id_str = nanoid::nanoid!(10);
        let key_id_hstring = HSTRING::from(key_id_str.as_str());

        let mut h_key = Default::default();
        let alg_id_pcwstr = asymmetric_spec_to_pcwstr(spec.asym_spec)?;

        let dw_flags = if spec.ephemeral {
            0 // Ephemeral keys are not persisted
        } else {
            NCRYPT_OVERWRITE_KEY_FLAG.0 // Persisted keys can be overwritten
        };

        execute_ncrypt_function!(@result NCryptCreatePersistedKey(
            self.provider_handle.0,
            &mut h_key,
            alg_id_pcwstr,
            if spec.ephemeral { PCWSTR::null() } else { PCWSTR(key_id_hstring.as_ptr()) },
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(dw_flags),
        ))?;
        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        // Set key length for RSA/ECC
        let key_len_bits = get_asymmetric_key_length_bits(spec.asym_spec)?;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_LENGTH_PROPERTY,
            &key_len_bits.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Set key usage
        let mut key_usage_flags_val = 0;
        if spec.cipher.is_some() {
            // If a cipher is specified, assume encryption/decryption usage
            key_usage_flags_val |= NCRYPT_ALLOW_DECRYPT_FLAG;
        }
        // Always allow signing for key pairs (can be restricted by policy later if needed)
        key_usage_flags_val |= NCRYPT_ALLOW_SIGNING_FLAG;
        // NCRYPT_ALLOW_KEY_AGREEMENT_FLAG for DH/ECDH, but we handle DH separately.

        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage_flags_val.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Set export policy
        let export_policy = if spec.non_exportable {
            0 // Disallow plaintext export
        } else {
            NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
        };
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &export_policy.to_le_bytes(),
            NCRYPT_SILENT_FLAG
        ))?;

        execute_ncrypt_function!(@result NCryptFinalizeKey(key_handle_wrapper.0, NCRYPT_SILENT_FLAG))?;

        if !spec.ephemeral {
            if let Some(sm) = &self.storage_manager {
                let key_data_to_store = KeyData {
                    id: key_id_str.clone(),
                    secret_data: None, // Key material in TPM
                    public_data: None, // Can be derived, or stored if fetched once
                    additional_data: None,
                    spec: Spec::KeyPairSpec(spec),
                };
                sm.store(key_id_str.clone(), key_data_to_store)?;
            }
        }

        let windows_key_pair_handle = WindowsKeyPairHandle {
            key_id: key_id_str,
            key_handle: key_handle_wrapper,
            spec,
            public_key_bytes: None,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyPairHandle {
            implementation: windows_key_pair_handle.into(),
        })
    }

    #[instrument(skip(self), err)]
    fn load_key_pair(&mut self, key_id: String) -> Result<KeyPairHandle, CalError> {
        let storage_manager = self.storage_manager.as_ref().ok_or_else(|| {
            CalError::failed_operation(
                "Ephemeral provider cannot load key pairs.".to_string(),
                true,
                None,
            )
        })?;

        let stored_data = storage_manager.get(key_id.clone())?;
        let spec = match stored_data.spec {
            Spec::KeyPairSpec(s) => s,
            _ => {
                return Err(CalError::bad_parameter(
                    "Attempted to load a non-key-pair as a key pair.".to_string(),
                    true,
                    None,
                ))
            }
        };

        if spec.ephemeral {
            // This case should ideally not happen if it's loaded from storage
            return Err(CalError::failed_operation(
                "Attempted to load an ephemeral key pair from storage.".to_string(),
                true,
                None,
            ));
        }

        let mut h_key = Default::default();
        let key_id_hstring = HSTRING::from(key_id.as_str());

        execute_ncrypt_function!(@result NCryptOpenKey(
            self.provider_handle.0,
            &mut h_key,
            PCWSTR(key_id_hstring.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        ))?;
        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        let windows_key_pair_handle = WindowsKeyPairHandle {
            key_id,
            key_handle: key_handle_wrapper,
            spec,
            public_key_bytes: None,
            storage_manager: self.storage_manager.clone(),
        };

        Ok(KeyPairHandle {
            implementation: windows_key_pair_handle.into(),
        })
    }

    #[instrument(skip(self, spec, _public_key, private_key), err)]
    fn import_key_pair(
        &mut self,
        spec: KeyPairSpec,
        _public_key: &[u8],
        private_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::failed_operation(
                "Ephemeral provider cannot import non-ephemeral key pairs.".to_owned(),
                true,
                None,
            ));
        }

        let key_id_str = nanoid::nanoid!(10);
        let key_id_hstring = HSTRING::from(key_id_str.as_str());
        let alg_id_pcwstr = asymmetric_spec_to_pcwstr(spec.asym_spec)?;

        // The private_key data should be in BCRYPT_ECCPRIVATE_BLOB or BCRYPT_RSAPRIVATE_BLOB format.
        // These blobs typically include the public key material as well.
        let blob_type_pcwstr = match spec.asym_spec {
            crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA1024
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA2048
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA3072
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA4096
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA8192 => {
                BCRYPT_RSAPRIVATE_BLOB
            }
            crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::P256
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::P384
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::P521 => {
                BCRYPT_ECCPRIVATE_BLOB
            }
            _ => {
                return Err(CalError::unsupported_algorithm(format!(
                    "Unsupported asymmetric spec {:?} for import.",
                    spec.asym_spec
                )))
            }
        };

        let mut h_key = Default::default();
        let dw_import_flags_val = 0;
        let dw_import_flags = NCRYPT_FLAGS(dw_import_flags_val);

        execute_ncrypt_function!(@result NCryptImportKey(
            self.provider_handle.0,
            None, // hImportKey (no wrapping key)
            blob_type_pcwstr,
            None, // pParameterList
            &mut h_key,
            private_key, // pbData (the private key blob)
            dw_import_flags,
        ))?;
        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        // Set properties for the imported key
        let alg_id_utf16: Vec<u16> = unsafe { alg_id_pcwstr.as_wide() }.into();
        let alg_id_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(alg_id_utf16.as_ptr() as *const u8, alg_id_utf16.len() * 2)
        };
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_ALGORITHM_PROPERTY,
            alg_id_bytes,
            NCRYPT_SILENT_FLAG,
        ))?;

        if !spec.ephemeral {
            let name_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    key_id_hstring.as_ptr() as *const u8,
                    key_id_hstring.len() * 2,
                )
            };
            execute_ncrypt_function!(@result NCryptSetProperty(
                key_handle_wrapper.0.into(),
                NCRYPT_NAME_PROPERTY,
                name_bytes,
                NCRYPT_OVERWRITE_KEY_FLAG, // If key with this name exists, overwrite it
            ))?;
        }

        let key_len_bits = get_asymmetric_key_length_bits(spec.asym_spec)?;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_LENGTH_PROPERTY,
            &key_len_bits.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        let mut key_usage_flags_val = NCRYPT_ALLOW_SIGNING_FLAG;
        if spec.cipher.is_some() {
            key_usage_flags_val |= NCRYPT_ALLOW_DECRYPT_FLAG;
        }
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage_flags_val.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        let export_policy = if spec.non_exportable {
            0
        } else {
            NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
        };
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &export_policy.to_le_bytes(),
            NCRYPT_SILENT_FLAG
        ))?;

        execute_ncrypt_function!(@result NCryptFinalizeKey(key_handle_wrapper.0, NCRYPT_SILENT_FLAG))?;

        if !spec.ephemeral {
            if let Some(sm) = &self.storage_manager {
                let key_data_to_store = KeyData {
                    id: key_id_str.clone(),
                    secret_data: None,
                    public_data: None, // Could fetch and store if needed
                    additional_data: None,
                    spec: Spec::KeyPairSpec(spec),
                };
                sm.store(key_id_str.clone(), key_data_to_store)?;
            }
        }

        let windows_key_pair_handle = WindowsKeyPairHandle {
            key_id: key_id_str,
            key_handle: key_handle_wrapper,
            spec,
            public_key_bytes: None,
            storage_manager: self.storage_manager.clone(),
        };
        Ok(KeyPairHandle {
            implementation: windows_key_pair_handle.into(),
        })
    }

    #[instrument(skip(self, spec, public_key), err)]
    fn import_public_key(
        &mut self,
        spec: KeyPairSpec,
        public_key: &[u8],
    ) -> Result<KeyPairHandle, CalError> {
        // Importing only a public key means we can't perform private key operations.
        // The resulting NCRYPT_KEY_HANDLE will only have the public part.
        if self.storage_manager.is_none() && !spec.ephemeral {
            return Err(CalError::failed_operation(
                "Ephemeral provider cannot import non-ephemeral public keys.".to_owned(),
                true,
                None,
            ));
        }

        let key_id_str = nanoid::nanoid!(10);
        let key_id_hstring = HSTRING::from(key_id_str.as_str());
        let alg_id_pcwstr = asymmetric_spec_to_pcwstr(spec.asym_spec)?;

        let blob_type_pcwstr = match spec.asym_spec {
            crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA1024
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA2048
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA3072
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA4096
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::RSA8192 => {
                BCRYPT_RSAPUBLIC_BLOB
            }
            crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::P256
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::P384
            | crate::common::crypto::algorithms::encryption::AsymmetricKeySpec::P521 => {
                BCRYPT_ECCPUBLIC_BLOB
            }
            _ => {
                return Err(CalError::unsupported_algorithm(format!(
                    "Unsupported asymmetric spec {:?} for public key import.",
                    spec.asym_spec
                )))
            }
        };

        let mut h_key = Default::default();
        // For public keys, dwFlags for NCryptImportKey is typically 0.
        // If it's persisted, it's named via NCryptSetProperty.
        let dw_import_flags = NCRYPT_FLAGS(0);

        execute_ncrypt_function!(@result NCryptImportKey(
            self.provider_handle.0,
            None,
            blob_type_pcwstr,
            None,
            &mut h_key,
            public_key, // pbData (the public key blob)
            dw_import_flags,
        ))?;
        let key_handle_wrapper = NcryptKeyHandleWrapper(h_key);

        // Set properties
        let alg_id_utf16: Vec<u16> = unsafe { alg_id_pcwstr.as_wide() }.into();
        let alg_id_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(alg_id_utf16.as_ptr() as *const u8, alg_id_utf16.len() * 2)
        };
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_ALGORITHM_PROPERTY,
            alg_id_bytes,
            NCRYPT_SILENT_FLAG,
        ))?;

        if !spec.ephemeral {
            let name_bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    key_id_hstring.as_ptr() as *const u8,
                    key_id_hstring.len() * 2,
                )
            };
            execute_ncrypt_function!(@result NCryptSetProperty(
                key_handle_wrapper.0.into(),
                NCRYPT_NAME_PROPERTY,
                name_bytes,
                NCRYPT_OVERWRITE_KEY_FLAG,
            ))?;
        }

        let key_len_bits = get_asymmetric_key_length_bits(spec.asym_spec)?;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_LENGTH_PROPERTY,
            &key_len_bits.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // For a public-only key, usage is typically verification and encryption.
        let key_usage_flags_val = NCRYPT_ALLOW_SIGNING_FLAG;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_KEY_USAGE_PROPERTY,
            &key_usage_flags_val.to_le_bytes(),
            NCRYPT_SILENT_FLAG,
        ))?;

        // Export policy for public-only keys is less critical but set for consistency.
        // Plaintext export of a public key is always allowed.
        let export_policy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        execute_ncrypt_function!(@result NCryptSetProperty(
            key_handle_wrapper.0.into(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            &export_policy.to_le_bytes(),
            NCRYPT_SILENT_FLAG
        ))?;

        execute_ncrypt_function!(@result NCryptFinalizeKey(key_handle_wrapper.0, NCRYPT_SILENT_FLAG))?;

        if !spec.ephemeral {
            if let Some(sm) = &self.storage_manager {
                let key_data_to_store = KeyData {
                    id: key_id_str.clone(),
                    secret_data: None,                      // No private key
                    public_data: Some(public_key.to_vec()), // Store the imported public key
                    additional_data: None,
                    spec: Spec::KeyPairSpec(spec),
                };
                sm.store(key_id_str.clone(), key_data_to_store)?;
            }
        }

        let windows_key_pair_handle = WindowsKeyPairHandle {
            key_id: key_id_str,
            key_handle: key_handle_wrapper,
            spec,
            public_key_bytes: Some(public_key.to_vec()),
            storage_manager: self.storage_manager.clone(),
        };
        Ok(KeyPairHandle {
            implementation: windows_key_pair_handle.into(),
        })
    }

    fn start_ephemeral_dh_exchange(
        &mut self,
        spec: KeyPairSpec,
    ) -> Result<crate::common::DHExchange, CalError> {
        error!(
            "start_ephemeral_dh_exchange not yet implemented for WindowsProvider (spec: {:?})",
            spec
        );
        Err(CalError::not_implemented())
    }

    fn dh_exchange_from_keys(
        &mut self,
        public_key: &[u8],
        private_key: &[u8],
        spec: KeyPairSpec,
    ) -> Result<crate::common::DHExchange, CalError> {
        error!("dh_exchange_from_keys not yet implemented for WindowsProvider (spec: {:?}, pk_len: {}, sk_len: {})", spec, public_key.len(), private_key.len());
        Err(CalError::not_implemented())
    }

    #[instrument(skip(self), err)]
    fn get_all_keys(&self) -> Result<Vec<(String, Spec)>, CalError> {
        if let Some(sm) = &self.storage_manager {
            sm.get_all_keys()
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
        "WindowsTpmProvider".to_string()
    }

    fn get_capabilities(&self) -> Option<ProviderConfig> {
        WindowsProviderFactory::default().get_capabilities(self.impl_config.clone())
    }

    #[instrument(skip(self, password, salt), err)]
    fn derive_key_from_password(
        &self,
        password: &str,
        salt: &[u8],
        algorithm: KeySpec,
        kdf: KDF,
    ) -> Result<KeyHandle, CalError> {
        error!("derive_key_from_password not implemented for WindowsProvider (password_len: {}, salt_len: {}, algo: {:?}, kdf: {:?})", password.len(), salt.len(), algorithm, kdf);
        Err(CalError::not_implemented())
    }

    #[instrument(skip(self, base_key, context), err)]
    fn derive_key_from_base(
        &self,
        base_key: &[u8],
        key_id: u64,
        context: &str,
        spec: KeySpec,
    ) -> Result<KeyHandle, CalError> {
        error!("derive_key_from_base not implemented for WindowsProvider (base_key_len: {}, key_id: {}, context: {}, spec: {:?})", base_key.len(), key_id, context, spec);
        Err(CalError::not_implemented())
    }

    #[instrument(skip(self, input), err)]
    fn hash(&self, input: &[u8], hash_algo: CryptoHash) -> Result<Vec<u8>, CalError> {
        let bcrypt_alg_id = crypto_hash_to_pcwstr(hash_algo)?;
        let mut h_alg = BCRYPT_ALG_HANDLE::default();
        let mut h_hash = BCRYPT_HASH_HANDLE::default();
        let mut hash_output = Vec::new();

        execute_ncrypt_function!(BCryptOpenAlgorithmProvider(
            &mut h_alg,
            bcrypt_alg_id,
            None,
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        ))?;

        // Scope for RAII-like cleanup of BCrypt handles
        let result = (|| {
            let mut object_len_value: u32 = 0;
            let mut bytes_copied_object_len: u32 = 0;
            let object_len_buffer: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut object_len_value as *mut u32 as *mut u8,
                    mem::size_of::<u32>(),
                )
            };
            execute_ncrypt_function!(BCryptGetProperty(
                h_alg.into(),
                BCRYPT_OBJECT_LENGTH,
                Some(object_len_buffer),
                &mut bytes_copied_object_len,
                0,
            ))?;
            if bytes_copied_object_len != mem::size_of::<u32>() as u32 {
                return Err(CalError::failed_operation(
                    "BCryptGetProperty for BCRYPT_OBJECT_LENGTH returned unexpected size."
                        .to_string(),
                    true,
                    None,
                ));
            }
            let mut hash_object = vec![0u8; object_len_value as usize];

            let mut hash_len_value: u32 = 0;
            let mut bytes_copied_hash_len: u32 = 0;
            let hash_len_buffer: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut hash_len_value as *mut u32 as *mut u8,
                    mem::size_of::<u32>(),
                )
            };
            execute_ncrypt_function!(BCryptGetProperty(
                h_alg.into(),
                BCRYPT_HASH_LENGTH,
                Some(hash_len_buffer),
                &mut bytes_copied_hash_len,
                0,
            ))?;
            if bytes_copied_hash_len != mem::size_of::<u32>() as u32 {
                return Err(CalError::failed_operation(
                    "BCryptGetProperty for BCRYPT_HASH_LENGTH returned unexpected size."
                        .to_string(),
                    true,
                    None,
                ));
            }
            hash_output.resize(hash_len_value as usize, 0);

            execute_ncrypt_function!(BCryptCreateHash(
                h_alg,
                &mut h_hash,
                Some(&mut hash_object),
                None, // No key for plain hash
                0,
            ))?;

            execute_ncrypt_function!(BCryptHashData(h_hash, input, 0))?;
            execute_ncrypt_function!(BCryptFinishHash(h_hash, &mut hash_output, 0))?;
            Ok(hash_output.clone())
        })();

        if !h_hash.is_invalid() {
            let _ = unsafe { BCryptDestroyHash(h_hash) };
        }
        if !h_alg.is_invalid() {
            let _ = unsafe { BCryptCloseAlgorithmProvider(h_alg, 0) };
        }
        result
    }

    fn get_random(&self, len: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; len];
        // BCryptGenRandom can fail, but this interface doesn't return Result.
        // We'll panic on failure, or you might consider changing the trait.
        execute_ncrypt_function!(BCryptGenRandom(
            None, // Use system preferred RNG
            &mut buffer,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        ))
        .expect("BCryptGenRandom failed");
        buffer
    }
}

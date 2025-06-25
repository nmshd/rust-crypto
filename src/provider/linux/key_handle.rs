use std::sync::{Arc, Mutex};

use itertools::Itertools;
use tracing::debug;
use tss_esapi::{
    interface_types::algorithm::SymmetricMode,
    structures::{InitialValue, MaxBuffer, Private, Public},
};

use crate::{
    common::{traits::key_handle::KeyHandleImpl, KeyHandle},
    prelude::{CalError, KeySpec},
    provider::linux::{
        conversion::{get_sym_mode, pad_pkcs7, unpad_pkcs7},
        provider::LinuxProvider,
    },
    storage::StorageManager,
};

use anyhow::anyhow;
use std::fmt::Debug;

#[derive(Clone)]
pub(crate) struct LinuxKeyHandle {
    pub(crate) key_id: String,
    pub(crate) spec: KeySpec,
    pub(crate) storage_manager: Option<StorageManager>,
    pub(crate) provider: LinuxProvider,
    pub(crate) key_data_private: Private,
    pub(crate) key_data_public: Public,
}

impl Debug for LinuxKeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("LinuxKeyHandle").finish()
    }
}

impl KeyHandleImpl for LinuxKeyHandle {
    fn encrypt_data(&self, data: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CalError> {
        let iv = self
            .spec
            .cipher
            .check_or_generate_iv(iv, &self.provider)
            .map_err(|_| CalError::bad_parameter("bad iv provided", true, None))?;

        let mut context = self.provider.context.lock().unwrap();

        let key_handle = context
            .load(
                self.provider.primary_key,
                self.key_data_private.clone(),
                self.key_data_public.clone(),
            )
            .map_err(|e| {
                CalError::failed_operation("failed to load key handle", false, Some(anyhow!(e)))
            })?;

        let mode = get_sym_mode(self.spec.cipher)?;

        // add padding if CBC is used
        let buffer = if mode == SymmetricMode::Cbc {
            pad_pkcs7(data, self.spec.cipher.len())
        } else {
            data.to_vec()
        };

        let res = if buffer.len() > MaxBuffer::MAX_SIZE {
            let (iv, encrypted) = buffer
                .into_iter()
                .chunks(MaxBuffer::MAX_SIZE)
                .into_iter()
                .fold(
                    Ok((InitialValue::try_from(iv).unwrap(), vec![])),
                    |acc, data_chunk| {
                        if let Ok((iv, mut data)) = acc {
                            context
                                .encrypt_decrypt_2(
                                    key_handle,
                                    false,
                                    mode,
                                    MaxBuffer::try_from(data_chunk.collect::<Vec<u8>>()).unwrap(),
                                    iv,
                                )
                                .map_err(|e| {
                                    CalError::failed_operation(
                                        "failed to encrypt",
                                        false,
                                        Some(anyhow!(e)),
                                    )
                                })
                                .map(|(encrypted, iv_out)| {
                                    data.extend_from_slice(encrypted.value());
                                    (iv_out, data)
                                })
                        } else {
                            // short circuit error
                            acc
                        }
                    },
                )
                .map_err(|e| {
                    CalError::failed_operation("failed to encrypt", false, Some(anyhow!(e)))
                })?;
            Ok((encrypted, iv.to_vec()))
        } else {
            debug!("not chunked");
            let (encrypted, _) = context
                .encrypt_decrypt_2(
                    key_handle,
                    false,
                    mode,
                    MaxBuffer::try_from(buffer).unwrap(),
                    InitialValue::try_from(iv.clone()).unwrap(),
                )
                .map_err(|e| {
                    CalError::failed_operation("failed to encrypt", false, Some(anyhow!(e)))
                })?;
            Ok((encrypted.to_vec(), iv))
        };

        let _ = context.flush_context(key_handle.into());
        res
    }

    fn decrypt_data(&self, encrypted_data: &[u8], iv: &[u8]) -> Result<Vec<u8>, CalError> {
        let mut context = self.provider.context.lock().unwrap();

        let key_handle = context
            .load(
                self.provider.primary_key,
                self.key_data_private.clone(),
                self.key_data_public.clone(),
            )
            .map_err(|e| {
                CalError::failed_operation("failed to load key handle", false, Some(anyhow!(e)))
            })?;

        let mode = get_sym_mode(self.spec.cipher)?;

        let decrypted = if encrypted_data.len() > MaxBuffer::MAX_SIZE {
            let (_, encrypted) = encrypted_data
                .into_iter()
                .chunks(MaxBuffer::MAX_SIZE)
                .into_iter()
                .fold(
                    Ok((InitialValue::try_from(iv).unwrap(), vec![])),
                    |acc, data_chunk| {
                        if let Ok((iv, mut data)) = acc {
                            context
                                .encrypt_decrypt_2(
                                    key_handle,
                                    true,
                                    mode,
                                    MaxBuffer::try_from(
                                        data_chunk.map(|v| *v).collect::<Vec<u8>>(),
                                    )
                                    .unwrap(),
                                    iv,
                                )
                                .map_err(|e| {
                                    CalError::failed_operation(
                                        "failed to decrypt",
                                        false,
                                        Some(anyhow!(e)),
                                    )
                                })
                                .map(|(encrypted, iv_out)| {
                                    data.extend_from_slice(encrypted.value());
                                    (iv_out, data)
                                })
                        } else {
                            // short circuit error
                            acc
                        }
                    },
                )
                .map_err(|e| {
                    CalError::failed_operation("failed to decrypt", false, Some(anyhow!(e)))
                })?;
            Ok::<Vec<u8>, CalError>(encrypted)
        } else {
            debug!("not chunked");
            let (encrypted, _) = context
                .encrypt_decrypt_2(
                    key_handle,
                    true,
                    mode,
                    MaxBuffer::try_from(encrypted_data).unwrap(),
                    InitialValue::try_from(iv).unwrap(),
                )
                .map_err(|e| {
                    CalError::failed_operation("failed to decrypt", false, Some(anyhow!(e)))
                })?;
            Ok::<Vec<u8>, CalError>(encrypted.to_vec())
        }?;

        let _ = context.flush_context(key_handle.into());

        if mode == SymmetricMode::Cbc {
            unpad_pkcs7(&decrypted)
        } else {
            Ok(decrypted)
        }
    }

    fn hmac(&self, data: &[u8]) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn verify_hmac(&self, data: &[u8], hmac: &[u8]) -> Result<bool, CalError> {
        Err(CalError::not_implemented())
    }

    fn derive_key(&self, nonce: &[u8]) -> Result<KeyHandle, CalError> {
        Err(CalError::not_implemented())
    }

    fn extract_key(&self) -> Result<Vec<u8>, CalError> {
        Err(CalError::not_implemented())
    }

    fn id(&self) -> Result<String, CalError> {
        Ok(self.key_id.clone())
    }

    fn delete(self) -> Result<(), CalError> {
        Err(CalError::not_implemented())
    }

    fn spec(&self) -> KeySpec {
        self.spec
    }
}

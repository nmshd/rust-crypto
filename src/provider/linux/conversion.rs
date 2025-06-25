use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::interface_types::algorithm::SymmetricMode;
use tss_esapi::structures::{Digest, PublicBuilder};
use tss_esapi::structures::{Public, SymmetricCipherParameters};

use crate::prelude::CalError;
use crate::prelude::CryptoHash;
use crate::prelude::KeySpec;

use crate::prelude::Cipher;
use anyhow::anyhow;

impl TryInto<Public> for KeySpec {
    type Error = CalError;

    fn try_into(self) -> Result<Public, Self::Error> {
        if self.non_exportable == false {
            return Err(CalError::bad_parameter(
                "TPM key can never be exportable",
                true,
                None,
            ));
        }

        let object_attributes = ObjectAttributesBuilder::new()
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .map_err(|e| {
                CalError::failed_operation(
                    "failed to create object attributes",
                    false,
                    Some(anyhow!(e)),
                )
            })?;

        let sym_param: SymmetricCipherParameters = self.cipher.try_into()?;

        PublicBuilder::new()
            .with_public_algorithm(
                tss_esapi::interface_types::algorithm::PublicAlgorithm::SymCipher,
            )
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(sym_param)
            .with_symmetric_cipher_unique_identifier(Digest::default())
            .with_name_hashing_algorithm(self.signing_hash.try_into()?)
            .build()
            .map_err(|e| {
                CalError::failed_operation(
                    "failed to create public key definition",
                    false,
                    Some(anyhow!(e)),
                )
            })
    }
}

impl TryInto<tss_esapi::interface_types::algorithm::HashingAlgorithm> for CryptoHash {
    type Error = CalError;

    fn try_into(
        self,
    ) -> Result<tss_esapi::interface_types::algorithm::HashingAlgorithm, Self::Error> {
        match self {
            CryptoHash::Sha2_224 => Err(CalError::bad_parameter(
                "TPM2.0 does not support Sha2_224",
                true,
                None,
            )),
            CryptoHash::Sha2_256 => {
                Ok(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
            }
            CryptoHash::Sha2_384 => {
                Ok(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha384)
            }
            CryptoHash::Sha2_512 => {
                Ok(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha512)
            }
            CryptoHash::Sha2_512_224 => Err(CalError::bad_parameter(
                "TPM2.0 does not support Sha2_512_224",
                true,
                None,
            )),
            CryptoHash::Sha2_512_256 => Err(CalError::bad_parameter(
                "TPM2.0 does not support Sha2_512_256",
                true,
                None,
            )),
            CryptoHash::Sha3_224 => Err(CalError::bad_parameter(
                "TPM2.0 does not support Sha3_224",
                true,
                None,
            )),
            CryptoHash::Sha3_256 => {
                Ok(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha3_256)
            }
            CryptoHash::Sha3_384 => {
                Ok(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha3_384)
            }
            CryptoHash::Sha3_512 => {
                Ok(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha3_512)
            }
            CryptoHash::Blake2b => Err(CalError::bad_parameter(
                "TPM2.0 does not support Blake2b",
                true,
                None,
            )),
        }
    }
}

impl TryInto<SymmetricCipherParameters> for Cipher {
    type Error = CalError;

    fn try_into(self) -> Result<SymmetricCipherParameters, Self::Error> {
        match self {
            Cipher::AesGcm128 => Err(CalError::bad_parameter(
                "TPM2.0 does not support AesGcm128",
                true,
                None,
            )),
            Cipher::AesGcm256 => Err(CalError::bad_parameter(
                "TPM2.0 does not support AesGcm256",
                true,
                None,
            )),
            Cipher::AesCbc128 => Ok(SymmetricCipherParameters::new(
                tss_esapi::structures::SymmetricDefinitionObject::Aes {
                    key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
                    mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cbc,
                },
            )),
            Cipher::AesCbc256 => Ok(SymmetricCipherParameters::new(
                tss_esapi::structures::SymmetricDefinitionObject::Aes {
                    key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
                    mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cbc,
                },
            )),
            Cipher::ChaCha20Poly1305 => Err(CalError::bad_parameter(
                "TPM2.0 does not support ChaCha20Poly1305",
                true,
                None,
            )),
            Cipher::XChaCha20Poly1305 => Err(CalError::bad_parameter(
                "TPM2.0 does not support XChaCha20Poly1305",
                true,
                None,
            )),
        }
    }
}

pub(super) fn get_sym_mode(cipher: Cipher) -> Result<SymmetricMode, CalError> {
    match cipher {
        Cipher::AesGcm128 => Err(CalError::bad_parameter(
            "TPM2.0 does not support Gcm",
            true,
            None,
        )),
        Cipher::AesGcm256 => Err(CalError::bad_parameter(
            "TPM2.0 does not support Gcm",
            true,
            None,
        )),
        Cipher::AesCbc128 => Ok(SymmetricMode::Cbc),
        Cipher::AesCbc256 => Ok(SymmetricMode::Cbc),
        Cipher::ChaCha20Poly1305 => Err(CalError::bad_parameter(
            "TPM2.0 does not support ChaCha20Poly1305",
            true,
            None,
        )),
        Cipher::XChaCha20Poly1305 => Err(CalError::bad_parameter(
            "TPM2.0 does not support ChaCha20Poly1305",
            true,
            None,
        )),
    }
}

pub(super) fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let data_pos = data.len();
    let over = data_pos % block_size;
    let mut buffer = data.to_vec();

    assert!(block_size < 256, "block size is too big for PKCS#7");

    let n = block_size - over;
    buffer.append(&mut vec![n as u8; n]);
    buffer
}

pub(super) fn unpad_pkcs7(data: &[u8]) -> Result<Vec<u8>, CalError> {
    if data.is_empty() {
        return Err(CalError::bad_parameter(
            "pkcs7 encoded data can't be empty",
            true,
            None,
        ));
    }
    let n = data[data.len() - 1];
    if n == 0 {
        return Err(CalError::bad_parameter(
            "pkcs7 encoded data has bad padding",
            true,
            None,
        ));
    }
    if n as usize > data.len() {
        return Err(CalError::bad_parameter(
            "pkcs7 encoded data has bigger blocksize than length",
            true,
            None,
        ));
    }

    if data[data.len() - (n as usize)..] != vec![n; n as usize] {
        return Err(CalError::bad_parameter(
            "pkcs7 encoded data has bad padding",
            true,
            None,
        ));
    }

    Ok(data[..data.len() - (n as usize)].to_vec())
}

#[cfg(test)]
mod tests {
    use crate::tests::setup;

    use super::*;
    use proptest::prelude::*;

    // Proptest strategy for generating a valid block size (1 to 255).
    // We use prop_oneof to sometimes favor the common AES block size of 16.
    fn block_size_strategy() -> impl Strategy<Value = usize> {
        prop_oneof![Just(16), 1..=255usize,]
    }

    // Proptest strategy for generating arbitrary byte data.
    fn data_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..1024),
            proptest::collection::vec(any::<u8>(), 0..20480)
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        #[test]
        fn test_pkcs7_padding_properties(
            data in data_strategy(),
            block_size in block_size_strategy()
        ) {
            setup();
            let original_len = data.len();
            let padded = pad_pkcs7(&data, block_size);

            prop_assert_eq!(padded.len() % block_size, 0, "Padded length is not a multiple of block size");

            prop_assert!(padded.len() > original_len, "Padded length is not greater than original length");

            prop_assert_eq!(&padded[..original_len], &data[..], "Original data was not preserved at the start of the padded output");

            let padding_len = padded.len() - original_len;
            prop_assert!(padding_len >= 1 && padding_len <= block_size, "Invalid number of padding bytes added");

            let padding_value = padding_len as u8;
            let padding_slice = &padded[original_len..];

            for &byte in padding_slice {
                prop_assert_eq!(byte, padding_value, "Padding byte has an incorrect value");
            }

            match unpad_pkcs7(&padded) {
                Ok(unpadded_data) => prop_assert_eq!(unpadded_data, &data[..], "Unpadded data does not match original data"),
                Err(_) => prop_assert!(false, "Unpadding failed on a correctly padded buffer"),
            }
        }
    }

    #[test]
    fn test_invalid_padding_is_rejected() {
        setup();
        let invalid_padded_data = b"YELLOW SUBMARINE\x01\x02\x03\x04";
        assert!(unpad_pkcs7(invalid_padded_data).is_err());

        let invalid_padded_data_2 = b"YELLOW SUBMARINE\x00\x00\x00\x00";
        assert!(unpad_pkcs7(invalid_padded_data_2).is_err());

        let invalid_padded_data_3 = b"YELLOW SUBMARINE\x11"; // 17
        assert!(unpad_pkcs7(invalid_padded_data_3).is_err());
    }
}

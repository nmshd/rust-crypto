#![allow(dead_code)]

use crate::{
    common::{
        crypto::algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, SymmetricMode},
            hashes::{Hash, Sha2Bits},
        },
        error::SecurityModuleError,
    },
    tpm::core::error::TpmError,
};

use super::config::EncryptionMode;

pub fn get_algorithm(enc: EncryptionMode) -> Result<String, SecurityModuleError> {
    Ok(match enc {
        EncryptionMode::Sym(algo) => match algo {
            BlockCiphers::Aes(_, _) => "AES",
            BlockCiphers::TripleDes(_) => "DESede",
            BlockCiphers::Des | BlockCiphers::Rc2(_) | BlockCiphers::Camellia(_, _) => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()))?
            }
        },
        EncryptionMode::ASym { algo, digest: _ } => match algo {
            AsymmetricEncryption::Rsa(_) => "RSA",
            AsymmetricEncryption::Ecc(_) => "EC",
        },
    }
    .to_owned())
}

pub fn get_cipher_mode(e_mode: EncryptionMode) -> Result<String, SecurityModuleError> {
    match e_mode {
        EncryptionMode::Sym(cipher) => match cipher {
            BlockCiphers::Aes(mode, _) => Ok(format!(
                "AES/{}/{}",
                get_sym_block_mode(mode)?,
                get_padding(e_mode)?
            )),
            BlockCiphers::TripleDes(_) => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
            }
            BlockCiphers::Des => Ok("DES".to_owned()),
            BlockCiphers::Rc2(_) => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
            }
            BlockCiphers::Camellia(_, _) => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
            }
        },
        EncryptionMode::ASym { algo, digest: _ } => match algo {
            AsymmetricEncryption::Rsa(_) => Ok(format!("RSA/ECB/{}", get_padding(e_mode)?)),
            AsymmetricEncryption::Ecc(_) => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
            }
        },
    }
}

pub fn get_sym_block_mode(mode: SymmetricMode) -> Result<String, SecurityModuleError> {
    Ok(match mode {
        SymmetricMode::Gcm => "GCM",
        SymmetricMode::Ecb => "ECB",
        SymmetricMode::Cbc => "CBC",
        SymmetricMode::Ctr => "CTR",
        SymmetricMode::Cfb | SymmetricMode::Ofb | SymmetricMode::Ccm => {
            Err(TpmError::UnsupportedOperation(
                "Only GCM, ECB, CBC and CTR as blockmodes supported".to_owned(),
            ))?
        }
    }
    .to_owned())
}

pub fn get_padding(mode: EncryptionMode) -> Result<String, SecurityModuleError> {
    Ok(match mode {
        EncryptionMode::Sym(BlockCiphers::Aes(_, _)) => "PKCS7Padding",
        EncryptionMode::ASym { algo: _, digest: _ } => "PKCS1Padding",
        _ => "NoPadding",
    }
    .to_owned())
}

pub fn get_signature_padding() -> Result<String, SecurityModuleError> {
    Ok("PKCS1".to_owned())
}

pub fn get_digest(digest: Hash) -> Result<String, SecurityModuleError> {
    match digest {
        Hash::Sha1 => Ok("SHA-1".to_owned()),
        Hash::Sha2(size) => match size {
            Sha2Bits::Sha224 => Ok("SHA-224".to_owned()),
            Sha2Bits::Sha256 => Ok("SHA-256".to_owned()),
            Sha2Bits::Sha384 => Ok("SHA-384".to_owned()),
            Sha2Bits::Sha512 => Ok("SHA-512".to_owned()),
            Sha2Bits::Sha512_224 | Sha2Bits::Sha512_256 => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
            }
        },
        Hash::Md5 => Ok("MD5".to_owned()),
        Hash::Sha3(_) | Hash::Md2 | Hash::Md4 | Hash::Ripemd160 => {
            Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
        }
    }
}

pub fn get_hash_name(hash: Hash) -> Result<String, SecurityModuleError> {
    match hash {
        Hash::Sha1 => Ok("SHA1".to_owned()),
        Hash::Sha2(size) => match size {
            Sha2Bits::Sha224 => Ok("SHA224".to_owned()),
            Sha2Bits::Sha256 => Ok("SHA256".to_owned()),
            Sha2Bits::Sha384 => Ok("SHA384".to_owned()),
            Sha2Bits::Sha512 => Ok("SHA512".to_owned()),
            Sha2Bits::Sha512_224 | Sha2Bits::Sha512_256 => {
                Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
            }
        },
        Hash::Md5 => Ok("MD5".to_owned()),
        Hash::Sha3(_) | Hash::Md2 | Hash::Md4 | Hash::Ripemd160 => {
            Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
        }
    }
}

pub fn get_key_size(algo: AsymmetricEncryption) -> Result<u32, SecurityModuleError> {
    match algo {
        AsymmetricEncryption::Rsa(size) => Ok(Into::<u32>::into(size)),
        AsymmetricEncryption::Ecc(_) => {
            Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
        }
    }
}

pub fn get_curve(algo: AsymmetricEncryption) -> Result<String, SecurityModuleError> {
    match algo {
        AsymmetricEncryption::Rsa(_) => {
            Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
        }
        AsymmetricEncryption::Ecc(scheme) => {
            let curve = match scheme {
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::EcDsa(v) => v,
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::EcDh(v) => v,
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::EcDaa(v) => v,
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::Sm2(v) => v,
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::EcSchnorr(v) => {
                    v
                }
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::EcMqv(v) => v,
                crate::common::crypto::algorithms::encryption::EccSchemeAlgorithm::Null => {
                    return Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
                }
            };
            Ok(match curve {
                crate::common::crypto::algorithms::encryption::EccCurves::P256 => "secp256r1",
                crate::common::crypto::algorithms::encryption::EccCurves::P384 => "secp384r1",
                crate::common::crypto::algorithms::encryption::EccCurves::P521 => "secp521r1",
                crate::common::crypto::algorithms::encryption::EccCurves::Secp256k1 => "secp256k1",
                crate::common::crypto::algorithms::encryption::EccCurves::BrainpoolP256r1 => {
                    "brainpoolP256r1"
                }
                crate::common::crypto::algorithms::encryption::EccCurves::BrainpoolP384r1 => {
                    "brainpoolP384r1"
                }
                crate::common::crypto::algorithms::encryption::EccCurves::BrainpoolP512r1 => {
                    "brainpoolP512r1"
                }
                crate::common::crypto::algorithms::encryption::EccCurves::BrainpoolP638 => {
                    return Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
                }
                crate::common::crypto::algorithms::encryption::EccCurves::Curve25519 => "X25519",
                crate::common::crypto::algorithms::encryption::EccCurves::Curve448 => "X448",
                crate::common::crypto::algorithms::encryption::EccCurves::Frp256v1 => {
                    return Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
                }
            }
            .to_owned())
        }
    }
}

pub fn get_signature_algorithm(mode: EncryptionMode) -> Result<String, SecurityModuleError> {
    match mode {
        EncryptionMode::Sym(_) => {
            Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
        }
        EncryptionMode::ASym { algo, digest } => {
            let part1 = match algo {
                AsymmetricEncryption::Rsa(_) => "RSA",
                AsymmetricEncryption::Ecc(_) => "ECDSA",
            };
            let part2 = get_hash_name(digest)?;

            Ok(format!("{part2}with{part1}"))
        }
    }
}

pub fn get_iv_len(cipher: BlockCiphers) -> Result<usize, SecurityModuleError> {
    Ok(match cipher {
        BlockCiphers::Aes(mode, _) => match mode {
            SymmetricMode::Gcm => 12,
            SymmetricMode::Ccm => 16,
            SymmetricMode::Ecb => 16,
            SymmetricMode::Cbc => 16,
            SymmetricMode::Cfb => 16,
            SymmetricMode::Ofb => 16,
            SymmetricMode::Ctr => 16,
        },
        BlockCiphers::TripleDes(_) => 8,
        BlockCiphers::Des | BlockCiphers::Rc2(_) | BlockCiphers::Camellia(_, _) => {
            return Err(TpmError::UnsupportedOperation("not supported".to_owned()).into())
        }
    })
}

pub fn store_iv(mut data: Vec<u8>, mut iv: Vec<u8>) -> Vec<u8> {
    iv.append(&mut data);
    iv
}

pub fn load_iv(data: &[u8], iv_size: usize) -> (Vec<u8>, Vec<u8>) {
    let iv = Vec::from(&data[0..iv_size]);
    let data = Vec::from(&data[iv_size..]);
    (data, iv)
}

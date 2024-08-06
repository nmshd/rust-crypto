use super::config::EncryptionMode;
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

pub enum Padding {
    None,
    PKCS7,
    PKCS1,
}

impl From<Padding> for String {
    fn from(padding: Padding) -> Self {
        match padding {
            Padding::None => "NoPadding".to_string(),
            Padding::PKCS7 => "PKCS7Padding".to_string(),
            Padding::PKCS1 => "PKCS1Padding".to_string(),
        }
    }
}

impl From<Hash> for String {
    fn from(hash: Hash) -> Self {
        match hash {
            Hash::Sha1 => "SHA-1".to_string(),
            Hash::Sha2(size) => match size {
                Sha2Bits::Sha224 => "SHA-224".to_string(),
                Sha2Bits::Sha256 => "SHA-256".to_string(),
                Sha2Bits::Sha384 => "SHA-384".to_string(),
                Sha2Bits::Sha512 => "SHA-512".to_string(),
                Sha2Bits::Sha512_224 => "SHA-512/224".to_string(),
                Sha2Bits::Sha512_256 => "SHA-512/256".to_string(),
            },
            Hash::Md5 => "MD5".to_string(),
            Hash::Sha3(_) => "SHA3".to_string(),
            Hash::Md2 => "MD2".to_string(),
            Hash::Md4 => "MD4".to_string(),
            Hash::Ripemd160 => "RIPEMD-160".to_string(),
        }
    }
}

impl From<Hash> for Result<String, SecurityModuleError> {
    fn from(hash: Hash) -> Self {
        match hash {
            Hash::Sha1 => Ok("SHA1".to_owned()),
            Hash::Sha2(size) => match size {
                Sha2Bits::Sha224 => Ok("SHA224".to_owned()),
                Sha2Bits::Sha256 => Ok("SHA256".to_owned()),
                Sha2Bits::Sha384 => Ok("SHA384".to_owned()),
                Sha2Bits::Sha512 => Ok("SHA512".to_owned()),
                _ => Err(TpmError::UnsupportedOperation(
                    "SHA-512/224 and SHA-512/256 are not supported".to_owned(),
                )
                .into()),
            },
            Hash::Md5 => Ok("MD5".to_owned()),
            _ => Err(TpmError::UnsupportedOperation("Algorithm not supported".to_owned()).into()),
        }
    }
}

impl From<BlockCiphers> for usize {
    fn from(value: BlockCiphers) -> Self {
        match value {
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
            _ => unimplemented!("not supported"),
        }
    }
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

impl TryFrom<SymmetricMode> for String {
    type Error = SecurityModuleError;

    fn try_from(mode: SymmetricMode) -> Result<Self, Self::Error> {
        #[allow(unreachable_patterns)]
        match mode {
            SymmetricMode::Ecb => Ok("ECB".to_string()),
            SymmetricMode::Cbc => Ok("CBC".to_string()),
            SymmetricMode::Cfb => Ok("CFB".to_string()),
            SymmetricMode::Ofb => Ok("OFB".to_string()),
            SymmetricMode::Gcm => Ok("GCM".to_string()),
            SymmetricMode::Ctr => Ok("CTR".to_string()),
            SymmetricMode::Ccm => Ok("CCM".to_string()),
            _ => Err(TpmError::UnsupportedOperation(
                "Only GCM, ECB, CBC, and CTR as block modes are supported".to_owned(),
            )
            .into()),
        }
    }
}

impl From<BlockCiphers> for Result<String, SecurityModuleError> {
    fn from(cipher: BlockCiphers) -> Self {
        match cipher {
            BlockCiphers::Aes(mode, _) => {
                let mode_str: String = mode.try_into()?;
                Ok(format!("AES/{}", mode_str))
            }
            BlockCiphers::TripleDes(_) => Ok("DESede".to_string()),
            BlockCiphers::Des => Ok("DES".to_string()),
            _ => Err(TpmError::UnsupportedOperation("Unsupported cipher".to_owned()).into()),
        }
    }
}

impl From<AsymmetricEncryption> for String {
    fn from(algo: AsymmetricEncryption) -> Self {
        match algo {
            AsymmetricEncryption::Rsa(_) => "RSA".to_string(),
            AsymmetricEncryption::Ecc(_) => "EC".to_string(),
        }
    }
}

impl From<EncryptionMode> for Result<String, SecurityModuleError> {
    fn from(value: EncryptionMode) -> Self {
        match value {
            EncryptionMode::Sym(cipher) => cipher.into(),
            EncryptionMode::ASym { algo, .. } => Ok(algo.into()),
        }
    }
}

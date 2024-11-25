use crate::common::{
    config::KeyPairSpec,
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, Cipher, SymmetricMode},
        hashes::{CryptoHash, Sha2Bits},
    },
    error::CalError,
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

impl From<CryptoHash> for String {
    fn from(hash: CryptoHash) -> Self {
        match hash {
            CryptoHash::Sha1 => "SHA-1".to_string(),
            CryptoHash::Sha2(size) => match size {
                Sha2Bits::Sha224 => "SHA-224".to_string(),
                Sha2Bits::Sha256 => "SHA-256".to_string(),
                Sha2Bits::Sha384 => "SHA-384".to_string(),
                Sha2Bits::Sha512 => "SHA-512".to_string(),
                Sha2Bits::Sha512_224 => "SHA-512/224".to_string(),
                Sha2Bits::Sha512_256 => "SHA-512/256".to_string(),
            },
            CryptoHash::Md5 => "MD5".to_string(),
            CryptoHash::Sha3(_) => "SHA3".to_string(),
            CryptoHash::Md2 => "MD2".to_string(),
            CryptoHash::Md4 => "MD4".to_string(),
            CryptoHash::Ripemd160 => "RIPEMD-160".to_string(),
        }
    }
}

pub fn get_hash_name(hash: CryptoHash) -> Result<String, CalError> {
    match hash {
        CryptoHash::Sha1 => Ok("SHA1".to_owned()),
        CryptoHash::Sha2(size) => match size {
            Sha2Bits::Sha224 => Ok("SHA224".to_owned()),
            Sha2Bits::Sha256 => Ok("SHA256".to_owned()),
            Sha2Bits::Sha384 => Ok("SHA384".to_owned()),
            Sha2Bits::Sha512 => Ok("SHA512".to_owned()),
            Sha2Bits::Sha512_224 | Sha2Bits::Sha512_256 => {
                Err(CalError::unsupported_algorithm(format!("{:?}", hash)))
            }
        },
        CryptoHash::Md5 => Ok("MD5".to_owned()),
        CryptoHash::Sha3(_) | CryptoHash::Md2 | CryptoHash::Md4 | CryptoHash::Ripemd160 => {
            Err(CalError::unsupported_algorithm(format!("{:?}", hash)))
        }
    }
}

pub fn get_mode_name(mode: SymmetricMode) -> Result<String, CalError> {
    match mode {
        SymmetricMode::Ecb => Ok("ECB".to_string()),
        SymmetricMode::Cbc => Ok("CBC".to_string()),
        SymmetricMode::Cfb => Ok("CFB".to_string()),
        SymmetricMode::Ofb => Ok("OFB".to_string()),
        SymmetricMode::Gcm => Ok("GCM".to_string()),
        SymmetricMode::Ctr => Ok("CTR".to_string()),
        SymmetricMode::Ccm => Ok("CCM".to_string()),
    }
}

pub fn get_cipher_padding(cipher: Cipher) -> String {
    match cipher {
        Cipher::Aes(SymmetricMode::Gcm, _) => "NoPadding",
        Cipher::Aes(_, _) => "PKCS7Padding",
        _ => "PKCS7Padding",
    }
    .to_owned()
}

pub fn get_sym_cipher_mode(cipher: Cipher) -> Result<String, CalError> {
    match cipher {
        Cipher::Aes(mode, _) => Ok(format!(
            "AES/{}/{}",
            get_mode_name(mode)?,
            get_cipher_padding(cipher)
        )),
        Cipher::TripleDes(_) => Ok("DESede/CBC/PKCS7Padding".to_owned()),
        Cipher::Des => Ok("DES/CBC/NoPadding".to_owned()),
        Cipher::Rc2(_) | Cipher::Camellia(_, _) | Cipher::Rc4 | Cipher::Chacha20(_) => {
            Err(CalError::unsupported_algorithm(format!("{:?}", cipher)))
        }
    }
}

pub fn get_asym_cipher_mode(asym_spec: AsymmetricKeySpec) -> Result<String, CalError> {
    match asym_spec {
        AsymmetricKeySpec::Rsa(_) => Ok("RSA/ECB/PKCS1Padding".to_owned()),
        AsymmetricKeySpec::Ecc {
            scheme: _,
            curve: _,
        } => Err(CalError::unsupported_algorithm(format!(
            "ECC encryption/decryption not supported: {:?}",
            asym_spec
        ))),
    }
}

impl From<Cipher> for Result<String, CalError> {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::Aes(mode, _) => Ok(format!("AES/{}", get_mode_name(mode)?)),
            Cipher::TripleDes(_) => Ok("DESede".to_string()),
            Cipher::Des => Ok("DES".to_string()),
            _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
        }
    }
}

pub(crate) fn get_cipher_name(cipher: Cipher) -> Result<String, CalError> {
    match cipher {
        Cipher::Aes(_, _) => Ok("AES".to_string()),
        Cipher::TripleDes(_) => Ok("DESede".to_string()),
        Cipher::Des => Ok("DES".to_string()),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
    }
}

impl From<AsymmetricKeySpec> for String {
    fn from(algo: AsymmetricKeySpec) -> Self {
        match algo {
            AsymmetricKeySpec::Rsa(_) => "RSA".to_string(),
            AsymmetricKeySpec::Ecc {
                scheme: _scheme,
                curve: _curve,
            } => "EC".to_string(),
        }
    }
}

pub fn get_signature_algorithm(spec: KeyPairSpec) -> Result<String, CalError> {
    let part1 = match spec.asym_spec {
        AsymmetricKeySpec::Rsa(_) => "RSA",
        AsymmetricKeySpec::Ecc {
            scheme: _,
            curve: _,
        } => "ECDSA",
    };
    let part2 = get_hash_name(spec.signing_hash)?;

    Ok(format!("{part2}with{part1}"))
}

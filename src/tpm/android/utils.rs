use crate::common::{
    config::KeyPairSpec,
    crypto::algorithms::{
        encryption::{AsymmetricKeySpec, Cipher},
        hashes::CryptoHash,
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
            CryptoHash::Sha2_224 => "SHA-224".to_string(),
            CryptoHash::Sha2_256 => "SHA-256".to_string(),
            CryptoHash::Sha2_384 => "SHA-384".to_string(),
            CryptoHash::Sha2_512 => "SHA-512".to_string(),
            CryptoHash::Sha2_512_224 => "SHA-512/224".to_string(),
            CryptoHash::Sha2_512_256 => "SHA-512/256".to_string(),
            CryptoHash::Sha3_256
            | CryptoHash::Sha3_224
            | CryptoHash::Sha3_384
            | CryptoHash::Sha3_512 => "SHA3".to_string(),
        }
    }
}

pub fn is_rsa(asym_spec: AsymmetricKeySpec) -> bool {
    match asym_spec {
        AsymmetricKeySpec::RSA1024
        | AsymmetricKeySpec::RSA2048
        | AsymmetricKeySpec::RSA3072
        | AsymmetricKeySpec::RSA4096
        | AsymmetricKeySpec::RSA8192 => true,
        _ => false,
    }
}

pub fn get_cipher_padding(cipher: Cipher) -> Result<Padding, CalError> {
    match cipher {
        Cipher::AesCbc128 | Cipher::AesCbc256 => Ok(Padding::PKCS7),
        Cipher::AesGcm128 | Cipher::AesGcm256 => Ok(Padding::None),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
    }
}

pub fn get_key_size(cipher: Cipher) -> Result<i32, CalError> {
    match cipher {
        Cipher::AesCbc128 | Cipher::AesGcm128 => Ok(128),
        Cipher::AesCbc256 | Cipher::AesGcm256 => Ok(256),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
    }
}

pub fn get_asym_key_size(asym_spec: AsymmetricKeySpec) -> Result<i32, CalError> {
    match asym_spec {
        AsymmetricKeySpec::RSA1024 => Ok(1024),
        AsymmetricKeySpec::RSA2048 => Ok(2048),
        AsymmetricKeySpec::RSA3072 => Ok(3072),
        AsymmetricKeySpec::RSA4096 => Ok(4096),
        AsymmetricKeySpec::RSA8192 => Ok(8192),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", asym_spec))),
    }
}

pub fn get_hash_name(hash: CryptoHash) -> Result<String, CalError> {
    match hash {
        CryptoHash::Sha2_224 => Ok("SHA224".to_owned()),
        CryptoHash::Sha2_256 => Ok("SHA256".to_owned()),
        CryptoHash::Sha2_384 => Ok("SHA384".to_owned()),
        CryptoHash::Sha2_512 => Ok("SHA512".to_owned()),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", hash))),
    }
}

pub fn get_mode_name(cipher: Cipher) -> Result<String, CalError> {
    match cipher {
        Cipher::AesCbc128 | Cipher::AesCbc256 => Ok("CBC".to_owned()),
        Cipher::AesGcm128 | Cipher::AesGcm256 => Ok("GCM".to_owned()),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
    }
}

pub fn get_sym_cipher_mode(cipher: Cipher) -> Result<String, CalError> {
    match cipher {
        Cipher::AesCbc128 => Ok("AES/CBC/PKCS7Padding".to_owned()),
        Cipher::AesCbc256 => Ok("AES/CBC/PKCS7Padding".to_owned()),
        Cipher::AesGcm128 => Ok("AES/GCM/NoPadding".to_owned()),
        Cipher::AesGcm256 => Ok("AES/GCM/NoPadding".to_owned()),
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
    }
}

pub fn get_asym_cipher_mode(asym_spec: AsymmetricKeySpec) -> Result<String, CalError> {
    match asym_spec {
        AsymmetricKeySpec::RSA1024
        | AsymmetricKeySpec::RSA2048
        | AsymmetricKeySpec::RSA3072
        | AsymmetricKeySpec::RSA4096
        | AsymmetricKeySpec::RSA8192 => Ok("RSA/ECB/PKCS1Padding".to_owned()),
        _ => Err(CalError::unsupported_algorithm(format!(
            "ECC encryption/decryption not supported: {:?}",
            asym_spec
        ))),
    }
}

impl From<Cipher> for Result<String, CalError> {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::AesCbc128 | Cipher::AesCbc256 => Ok("AES/CBC".to_string()),
            Cipher::AesGcm128 | Cipher::AesGcm256 => Ok("AES/GCM".to_string()),
            _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
        }
    }
}

pub(crate) fn get_cipher_name(cipher: Cipher) -> Result<String, CalError> {
    match cipher {
        Cipher::AesCbc128 | Cipher::AesCbc256 | Cipher::AesGcm128 | Cipher::AesGcm256 => {
            Ok("AES".to_string())
        }
        _ => Err(CalError::unsupported_algorithm(format!("{:?}", cipher))),
    }
}

impl From<AsymmetricKeySpec> for String {
    fn from(algo: AsymmetricKeySpec) -> Self {
        match algo {
            AsymmetricKeySpec::RSA1024
            | AsymmetricKeySpec::RSA2048
            | AsymmetricKeySpec::RSA3072
            | AsymmetricKeySpec::RSA4096
            | AsymmetricKeySpec::RSA8192 => "RSA".to_string(),
            AsymmetricKeySpec::BrainpoolP256r1
            | AsymmetricKeySpec::BrainpoolP384r1
            | AsymmetricKeySpec::BrainpoolP512r1
            | AsymmetricKeySpec::BrainpoolP638
            | AsymmetricKeySpec::Curve25519
            | AsymmetricKeySpec::Curve448
            | AsymmetricKeySpec::P256
            | AsymmetricKeySpec::P384
            | AsymmetricKeySpec::P521
            | AsymmetricKeySpec::Secp256k1
            | AsymmetricKeySpec::Frp256v1 => "EC".to_string(),
        }
    }
}

pub fn get_signature_algorithm(spec: KeyPairSpec) -> Result<String, CalError> {
    let part1 = match spec.asym_spec {
        AsymmetricKeySpec::RSA1024
        | AsymmetricKeySpec::RSA2048
        | AsymmetricKeySpec::RSA3072
        | AsymmetricKeySpec::RSA4096
        | AsymmetricKeySpec::RSA8192 => "RSA".to_string(),
        AsymmetricKeySpec::BrainpoolP256r1
        | AsymmetricKeySpec::BrainpoolP384r1
        | AsymmetricKeySpec::BrainpoolP512r1
        | AsymmetricKeySpec::BrainpoolP638
        | AsymmetricKeySpec::Curve25519
        | AsymmetricKeySpec::Curve448
        | AsymmetricKeySpec::P256
        | AsymmetricKeySpec::P384
        | AsymmetricKeySpec::P521
        | AsymmetricKeySpec::Secp256k1
        | AsymmetricKeySpec::Frp256v1 => "ECDSA".to_string(),
    };
    let part2 = get_hash_name(spec.signing_hash)?;

    Ok(format!("{part2}with{part1}"))
}

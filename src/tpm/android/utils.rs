use crate::{
    common::{
        crypto::algorithms::{
            encryption::AsymmetricEncryption,
            hashes::{Hash, Sha2Bits},
        },
        error::SecurityModuleError,
    },
    tpm::core::error::TpmError,
};

use super::AndroidProvider;

impl AndroidProvider {
    pub fn get_algorithm(&self) -> Result<String, SecurityModuleError> {
        let key_algo = self
            .key_algo
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?;

        Ok(match key_algo {
            AsymmetricEncryption::Rsa(_) => "RSA",
            AsymmetricEncryption::Ecc(_) => "EC",
        }
        .to_owned())
    }

    pub fn get_digest(&self) -> Result<String, SecurityModuleError> {
        let hash = self
            .hash
            .as_ref()
            .ok_or(SecurityModuleError::InitializationError(
                "Module is not initialized".to_owned(),
            ))?;

        match hash {
            Hash::Sha1 => Ok("SHA-1".to_owned()),
            Hash::Sha2(size) => match size {
                Sha2Bits::Sha224 => Ok("SHA-224".to_owned()),
                Sha2Bits::Sha256 => Ok("SHA-256".to_owned()),
                Sha2Bits::Sha384 => Ok("SHA-384".to_owned()),
                Sha2Bits::Sha512 => Ok("SHA-512".to_owned()),
                Sha2Bits::Sha512_224 | Sha2Bits::Sha512_256 => {
                    Err(TpmError::UnsupportedOperation("not supportet".to_owned()).into())
                }
            },
            Hash::Md5 => Ok("MD5".to_owned()),
            Hash::Sha3(_) | Hash::Md2 | Hash::Md4 | Hash::Ripemd160 => {
                Err(TpmError::UnsupportedOperation("not supportet".to_owned()).into())
            }
        }
    }

    pub fn get_key_size(&self) -> Option<u32> {
        let algorithm = self.key_algo.as_ref()?;

        let size = match algorithm {
            AsymmetricEncryption::Rsa(size) => Some(Into::<u32>::into(size.clone())),
            AsymmetricEncryption::Ecc(_) => None,
        };

        size
    }
}

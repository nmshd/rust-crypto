use super::YubiKeyProvider;
use crate::{
    common::{error::SecurityModuleError, traits::key_handle::KeyHandle},
    yubikey::core::error::YubiKeyError,
};
use base64::general_purpose;
use openssl::{
    ec::EcKey,
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::{Padding, Rsa},
    sign::Verifier,
};
use sha2::Sha256;
use tracing::instrument;
use yubikey::{
    piv::{self, algorithm::AlgorithmId, SlotId},
    MgmKey, YubiKey,
};

/// Provides cryptographic operations for asymmetric keys on a YubiKey,
/// such as signing, encryption, decryption, and signature verification.

/// Signs data using the cryptographic key on a YubiKey.
///
/// This method hashes the input data using SHA-256 and then signs the hash.
///
/// # Arguments
///
/// * `data` - The data to be signed.
///
/// # Returns
///
/// A `Result` containing the signature as a `Vec<u8>` on success, or a `yubikey::Error` on failure.
#[instrument]
fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>, yubikey::Error> {
    let data = data.to_vec();

    // Input gets hashed with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let data = hasher.finalize();
    let data: &[u8] = &data;

    //TODO After PIN input implementation in App, insert code for re-authentication
    let verify = self.yubikey.verify_pin("123456".as_ref());
    if !verify.is_ok() {
        return Error::WrongPin {
            tries: yubikey::get_pin_retries(),
        };
    }
    let auth = self.yubikey.authenticate(MgmKey::default());
    if !auth.is_ok() {
        return Error::AuthenticationError;
    }

    match self.key_algorithm {
        Ecc => {
            // Sign data
            let signature =
                piv::sign_data(self.yubikey, data, piv::AlgorithmId::EccP256, self.slot_id);

            match signature {
                Ok(buffer) => return buffer,
                Err(err) => return err,
            }
        }
        Rsa => {
            // TODO, doesn´t work yet
        }
        "_" => {
            return Error::NotSupported;
        }
    }
}

/// Decrypts data encrypted with the corresponding public key on a YubiKey.
/// Only works with PKCS#1 v1.5 padding.
/// Utilizes the YubiKey API for decryption.
///
/// # Arguments
///
/// * `encrypted_data` - The data to be decrypted.
///
/// # Returns
///
/// A `Result` containing the decrypted data as a `Vec<u8>` on success, or a `yubikey::Error` on failure.
#[instrument]
fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, yubikey::Error> {
    let encrypted_data = general_purpose::STANDARD.decode(encrypt_data.unwrap());
    let input: &[u8] = &encrypted_data;
    let decrypted: Result<der::zeroize::Zeroizing<Vec<u8>>, yubikey::Error>;

    match self.key_algorithm {
        "Rsa" => {
            decrypted =
                piv::decrypt_data(self.yubikey, input, piv::AlgorithmId::Rsa2048, self.slot_id);
        }
        "Ecc" => {
            // TODO, not tested, might work
        }
        "_" => Error::NotSupported,
    }
    fn remove_pkcs1_padding(buffer: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut pos = 2; // Start nach dem ersten Padding-Byte `0x02`
        if buffer[0] != 0 {
            return Err("Invalid padding");
        }
        // Überspringe alle non-zero Bytes
        while pos < buffer.len() && buffer[pos] != 0 {
            pos += 1;
        }
        if pos >= buffer.len() {
            return Err("No data after padding");
        }
        // Das erste `0x00` Byte überspringen, um die tatsächlichen Daten zu erhalten
        Ok(buffer[pos + 1..].to_vec())
    }
    match decrypted {
        Ok(buffer) => match remove_pkcs1_padding(&buffer) {
            Ok(data) => {
                return Ok(data);
            }
            Err(_) => return Err(Error::SizeError),
        },
        Err(err) => return Err("Decryption failed"),
    }
}

/// Encrypts data with the cryptographic key on a YubiKey.
///
/// Uses the YubiKey API for encryption.
///
/// # Arguments
///
/// * `data` - The data to be encrypted.
///
/// # Returns
///
/// A `Result` containing the encrypted data as a `Vec<u8>` on success, or a `yubikey::Error` on failure.
/// Möglicher Fehler: Müssen Daten vor dem returnen noch in Base64 umgewandelt werden?
#[instrument]
fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, yubikey::Error> {
    match self.key_algorithm {
        Rsa => {
            let rsa = Rsa::public_key_from_pem(self.pkey.trim().as_bytes())
                .map_err(|_| "failed to create RSA from public key PEM");
            let mut encrypted_data = vec![0; rsa.size() as usize];
            rsa.public_encrypt(data, &mut encrypted_data, Padding::PKCS1)
                .map_err(|_| "failed to encrypt data");
            return encrypted_data;
        }
        Ecc => {
            // TODO
        }
        "_" => Error::NotSupported,
    }
}

/// Verifies a signature against the provided data using the YubiKey.
///
/// This method hashes the input data using SHA-256 and then verifies the signature.
///
/// # Arguments
///
/// * `data` - The original data associated with the signature.
/// * `signature` - The signature to be verified.
///
/// # Returns
///
/// A `Result` indicating whether the signature is valid (`true`) or not (`false`),
/// or a `SecurityModuleError` on failure.
#[instrument]
fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<bool, SecurityModuleError> {
    match self.key_algorithm {
        Rsa => {
            let rsa = Rsa::public_key_from_pem(self.pkey.trim().as_bytes())
                .map_err(|_| "failed to create RSA from public key PEM");
            let key_pkey = PKey::from_rsa(rsa).unwrap();

            let mut verifier = Verifier::new(MessageDigest::sha256(), &key_pkey)
                .map_err(|_| "failed to create verifier");
            verifier
                .update(data)
                .map_err(|_| "failed to update verifier");
            verifier
                .verify(signature)
                .map_err(|_| "failed to verify signature")
        }
        Ecc => {
            let ecc = EcKey::public_key_from_pem(self.pkey.trim().as_bytes())
                .map_err(|_| "failed to create ECC from public key PEM");
            let ecc = PKey::from_ec_key(ecc).map_err(|_| "failed to create PKey from ECC");

            let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
                .map_err(|_| "failed to create verifier");
            verifier
                .update(data)
                .map_err(|_| "failed to update verifier");
            verifier
                .verify(signature)
                .map_err(|_| "failed to verify signature")
        }
        "_" => Err(Error::NotSupported),
    }
}

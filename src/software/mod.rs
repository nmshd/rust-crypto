use crate::common::{
    config::{KeyPairSpec, ProviderConfig, ProviderImplConfig, SecurityLevel},
    crypto::algorithms::{
        encryption::{
            AsymmetricKeySpec, ChCha20Mode, Cipher, EccCurve, EccSigningScheme, SymmetricMode,
        },
        hashes::{CryptoHash, Sha2Bits},
        KeyBits,
    },
    traits::module_provider::{ProviderFactory, ProviderImplEnum},
};
use ring::signature::{
    EcdsaSigningAlgorithm, VerificationAlgorithm, ECDSA_P256_SHA256_ASN1,
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA256_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
};
use std::collections::HashSet;

pub mod key_handle;
pub mod provider;

#[derive(Default)]
pub(crate) struct SoftwareProviderFactory {}

impl ProviderFactory for SoftwareProviderFactory {
    fn get_name(&self) -> String {
        "SoftwareProvider".to_owned()
    }

    fn get_capabilities(&self, _impl_config: ProviderImplConfig) -> ProviderConfig {
        let mut supported_asym_specs = HashSet::new();
        supported_asym_specs.insert(AsymmetricKeySpec::Ecc {
            scheme: EccSigningScheme::EcDaa,
            curve: EccCurve::P256,
        });

        let mut supported_hashes = HashSet::new();
        supported_hashes.insert(CryptoHash::Sha2(Sha2Bits::Sha256));
        supported_hashes.insert(CryptoHash::Sha2(Sha2Bits::Sha384));
        supported_hashes.insert(CryptoHash::Sha2(Sha2Bits::Sha512));

        ProviderConfig {
            min_security_level: SecurityLevel::Software,
            max_security_level: SecurityLevel::Software,
            supported_asym_spec: supported_asym_specs,
            supported_ciphers: HashSet::new(),
            supported_hashes,
        }
    }

    fn create_provider(&self, impl_config: ProviderImplConfig) -> ProviderImplEnum {
        Into::into(SoftwareProvider::new(impl_config))
    }
}

pub(crate) struct SoftwareProvider {
    impl_config: ProviderImplConfig,
}

impl SoftwareProvider {
    pub(crate) fn new(impl_config: ProviderImplConfig) -> Self {
        Self { impl_config }
    }
}

impl From<KeyPairSpec> for &'static EcdsaSigningAlgorithm {
    fn from(value: KeyPairSpec) -> Self {
        match value.asym_spec {
            AsymmetricKeySpec::Ecc { scheme, curve } => match (scheme, curve) {
                (EccSigningScheme::EcDsa, EccCurve::P256) => &ECDSA_P256_SHA256_ASN1_SIGNING,
                (EccSigningScheme::EcDsa, EccCurve::P384) => &ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => panic!("Unsupported ECC curve or scheme"),
            },
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<AsymmetricKeySpec> for &'static dyn VerificationAlgorithm {
    fn from(spec: AsymmetricKeySpec) -> Self {
        match spec {
            AsymmetricKeySpec::Ecc { scheme, curve } => match (scheme, curve) {
                (EccSigningScheme::EcDsa, EccCurve::P256) => &ECDSA_P256_SHA256_ASN1,
                (EccSigningScheme::EcDsa, EccCurve::P384) => &ECDSA_P384_SHA256_ASN1,
                _ => panic!("Unsupported ECC curve or scheme"),
            },
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<AsymmetricKeySpec> for &'static EcdsaSigningAlgorithm {
    fn from(spec: AsymmetricKeySpec) -> Self {
        match spec {
            AsymmetricKeySpec::Ecc { scheme, curve } => match (scheme, curve) {
                (EccSigningScheme::EcDsa, EccCurve::P256) => &ECDSA_P256_SHA256_ASN1_SIGNING,
                (EccSigningScheme::EcDsa, EccCurve::P384) => &ECDSA_P384_SHA384_ASN1_SIGNING,
                _ => panic!("Unsupported ECC curve or scheme"),
            },
            _ => panic!("Unsupported ECC curve or scheme"),
        }
    }
}

impl From<Cipher> for &'static ring::aead::Algorithm {
    fn from(cipher: Cipher) -> Self {
        match cipher {
            Cipher::Aes(mode, key_bits) => match (mode, key_bits) {
                (SymmetricMode::Gcm, KeyBits::Bits128) => &ring::aead::AES_128_GCM,
                (SymmetricMode::Gcm, KeyBits::Bits256) => &ring::aead::AES_256_GCM,
                _ => panic!("Unsupported AES mode or key size for AEAD"),
            },
            Cipher::Chacha20(mode) => match mode {
                ChCha20Mode::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
                _ => panic!("Unsupported cipher for AEAD"), // Handle other cases or return an error
            },
            Cipher::TripleDes(_triple_des_num_keys) => todo!(),
            Cipher::Des => todo!(),
            Cipher::Rc2(_rc2_key_bits) => todo!(),
            Cipher::Camellia(_symmetric_mode, _key_bits) => todo!(),
            Cipher::Rc4 => todo!(),
        }
    }
}

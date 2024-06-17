use crate::common::crypto::algorithms::encryption::{
    AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm, SymmetricMode,
    TripleDesNumKeys,
};
use crate::common::crypto::algorithms::hashes::{Hash, Sha2Bits};
use crate::common::crypto::algorithms::KeyBits;
use crate::common::crypto::{Capability, EncryptionMode};

pub fn get_capabilities() -> Vec<Capability> {
    vec![
        Capability {
            name: "ENC-AES-CBC-256",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Cbc, KeyBits::Bits256)),
        },
        Capability {
            name: "ENC-AES-CBC-128",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Cbc, KeyBits::Bits128)),
        },
        Capability {
            name: "ENC-DESede-CBC",
            mode: EncryptionMode::Sym(BlockCiphers::TripleDes(TripleDesNumKeys::Tdes2)),
        },
        Capability {
            name: "ENC-RSA-1024-256",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Rsa(KeyBits::Bits1024),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
        Capability {
            name: "ENC-RSA-2048-256",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Rsa(KeyBits::Bits2048),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
        Capability {
            name: "SIG-RSA-1024-256",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Rsa(KeyBits::Bits1024),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
        Capability {
            name: "SIG-RSA-2048-256",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Rsa(KeyBits::Bits2048),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
        Capability {
            name: "SIG-EC-DSA-256",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::Secp256k1)),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
    ]
}

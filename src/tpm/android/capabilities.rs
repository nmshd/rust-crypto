use crate::common::crypto::algorithms::encryption::{
    AsymmetricEncryption, BlockCiphers, SymmetricMode,
};
use crate::common::crypto::algorithms::hashes::{Hash, Sha2Bits};
use crate::common::crypto::algorithms::KeyBits;
use crate::common::crypto::{Capability, EncryptionMode};

pub fn get_capabilities() -> Vec<Capability> {
    vec![
        Capability {
            name: "AES-CBC-256",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Cbc, KeyBits::Bits256)),
        },
        Capability {
            name: "AES-CFB-256",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Cfb, KeyBits::Bits256)),
        },
        Capability {
            name: "AES-CTR-256",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Ctr, KeyBits::Bits256)),
        },
        Capability {
            name: "AES-ECB-256",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Ecb, KeyBits::Bits256)),
        },
        Capability {
            name: "AES-OFB-256",
            mode: EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Ofb, KeyBits::Bits256)),
        },
        Capability {
            name: "RSA-256",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Rsa(KeyBits::Bits256),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
        Capability {
            name: "RSA-512",
            mode: EncryptionMode::ASym {
                algo: AsymmetricEncryption::Rsa(KeyBits::Bits512),
                digest: Hash::Sha2(Sha2Bits::Sha256),
            },
        },
    ]
}

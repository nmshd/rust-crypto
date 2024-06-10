use crate::common::crypto::algorithms::encryption::{
    AsymmetricEncryption, BlockCiphers, SymmetricMode,
};
use crate::common::crypto::algorithms::hashes::{Hash, Sha2Bits};
use crate::common::crypto::algorithms::KeyBits;
use crate::common::crypto::EncryptionMode;

pub fn get_capabilities() -> Vec<EncryptionMode> {
    vec![
        EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Cbc, KeyBits::Bits256)),
        EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Cfb, KeyBits::Bits256)),
        EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Ctr, KeyBits::Bits256)),
        EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Ecb, KeyBits::Bits256)),
        EncryptionMode::Sym(BlockCiphers::Aes(SymmetricMode::Ofb, KeyBits::Bits256)),
        EncryptionMode::ASym {
            algo: AsymmetricEncryption::Rsa(KeyBits::Bits256),
            digest: Hash::Sha2(Sha2Bits::Sha256),
        },
        EncryptionMode::ASym {
            algo: AsymmetricEncryption::Rsa(KeyBits::Bits512),
            digest: Hash::Sha2(Sha2Bits::Sha256),
        },
    ]
}

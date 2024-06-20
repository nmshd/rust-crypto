use algorithms::encryption::{AsymmetricEncryption, BlockCiphers};
use algorithms::hashes::Hash;

pub mod algorithms;
pub mod pkcs;

#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug, Copy)]
pub enum KeyUsage {
    ClientAuth,
    Decrypt,
    SignEncrypt,
    CreateX509,
}

#[derive(Debug, Clone, Copy)]
pub enum EncryptionMode {
    Sym(BlockCiphers),
    ASym {
        algo: AsymmetricEncryption,
        digest: Hash,
    },
}

pub struct Capability {
    pub name: &'static str,
    pub mode: EncryptionMode,
}

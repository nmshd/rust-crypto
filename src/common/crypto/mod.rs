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

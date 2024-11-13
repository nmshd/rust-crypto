pub mod algorithms;
pub mod pkcs;

#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug, Copy)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum KeyUsage {
    ClientAuth,
    Decrypt,
    SignEncrypt,
    CreateX509,
}

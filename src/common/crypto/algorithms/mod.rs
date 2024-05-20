pub mod encryption;
pub mod hashes;

/// Represents the bit length of a cryptographic key.
///
/// This enum defines various key bit lengths commonly used in cryptography.
/// It provides a convenient way to specify and work with different key sizes.
///
/// The available key bit lengths are:
///
/// - `Bits128`: 128-bit key length
/// - `Bits192`: 192-bit key length
/// - `Bits256`: 256-bit key length
/// - `Bits512`: 512-bit key length
/// - `Bits1024`: 1024-bit key length
/// - `Bits2048`: 2048-bit key length
/// - `Bits3072`: 3072-bit key length
/// - `Bits4096`: 4096-bit key length
/// - `Bits8192`: 8192-bit key length
///
/// This enum can be converted to and from `u32` values using the `From` trait implementations.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum KeyBits {
    Bits128,
    Bits192,
    Bits256,
    Bits512,
    Bits1024,
    Bits2048,
    Bits3072,
    Bits4096,
    Bits8192,
}

impl From<KeyBits> for u32 {
    fn from(value: KeyBits) -> Self {
        match value {
            KeyBits::Bits128 => 128,
            KeyBits::Bits192 => 192,
            KeyBits::Bits256 => 256,
            KeyBits::Bits512 => 512,
            KeyBits::Bits1024 => 1024,
            KeyBits::Bits2048 => 2048,
            KeyBits::Bits3072 => 3072,
            KeyBits::Bits4096 => 4096,
            KeyBits::Bits8192 => 8192,
        }
    }
}

impl From<u32> for KeyBits {
    fn from(value: u32) -> Self {
        match value {
            128 => KeyBits::Bits128,
            192 => KeyBits::Bits192,
            256 => KeyBits::Bits256,
            512 => KeyBits::Bits512,
            1024 => KeyBits::Bits1024,
            2048 => KeyBits::Bits2048,
            3072 => KeyBits::Bits3072,
            4096 => KeyBits::Bits4096,
            8192 => KeyBits::Bits8192,
            _ => unimplemented!(),
        }
    }
}

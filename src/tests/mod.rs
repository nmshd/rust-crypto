//mod common;
#[cfg(feature = "hsm")]
mod hsm;

#[cfg(feature = "tpm")]
mod tpm;

#[cfg(feature = "nks")]
mod nks;

use crate::common::KeyPairHandle;

/// When going out of scope, deletes the key pair it holds.
#[allow(dead_code)]
struct CleanupKeyPair {
    key_pair_handle: KeyPairHandle,
}

impl Drop for CleanupKeyPair {
    fn drop(&mut self) {
        self.key_pair_handle
            .clone()
            .delete()
            .expect("Failed cleanup of key.");
    }
}

impl CleanupKeyPair {
    #[allow(dead_code)]
    fn new(key_pair_handle: KeyPairHandle) -> Self {
        Self { key_pair_handle }
    }
}

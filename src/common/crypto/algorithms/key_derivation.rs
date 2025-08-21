use serde::{Deserialize, Serialize};

/// Enum representing different secure key derivation functions
///
/// For clients Argon2d is recommended as it offers excellent brute force resistance.
/// ```
/// # use crypto_layer::prelude::*;
/// /// Taken from KeePass (12.03.2025)
/// /// https://keepass.info/help/base/security.html
/// let client_kdf = KDF::Argon2id(Argon2Options {
///            memory: 1048576,
///            iterations: 2,
///            parallelism: 4,
///        });
/// ```
///
/// For servers Argon2id is recommended as it also offers some side channel attack resistance.
/// ```
/// # use crypto_layer::prelude::*;
/// /// Taken from Password Storage Cheat Sheet (12.03.2025)
/// /// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
/// let server_kdf = KDF::Argon2id(Argon2Options {
///            memory: 19456,
///            iterations: 2,
///            parallelism: 1,
///        });
/// ```
// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub enum KDF {
    /// Strong brute force resistance, no side channel resistance.
    Argon2d(Argon2Options),
    /// Partial brute force and partial side channel resistance.
    Argon2id(Argon2Options),
    Argon2i(Argon2Options),
}

/// Configuration for KDF with Argon2
///
/// When in doubt use the default.
// flutter_rust_bridge:non_opaque
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-interface", derive(ts_rs::TS), ts(export))]
pub struct Argon2Options {
    /// Memory cost in kibibytes
    pub memory: u32,
    /// Number of iterations
    pub iterations: u32,
    /// Degree of parallelism
    pub parallelism: u32,
}

impl Default for Argon2Options {
    /// Defaults for servers.
    /// Taken from Password Storage Cheat Sheet (12.03.2025)
    /// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
    fn default() -> Self {
        Argon2Options {
            memory: 19456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Default for KDF {
    /// Defaults for servers.
    /// Taken from Password Storage Cheat Sheet (12.03.2025)
    /// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
    fn default() -> Self {
        KDF::Argon2id(Argon2Options::default())
    }
}

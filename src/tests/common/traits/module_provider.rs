#[cfg(feature = "hsm")]
use crate::hsm::core::instance::HsmType;
#[cfg(feature = "tpm")]
use crate::tpm::{core::instance::TpmType, TpmConfig};
use crate::{
    common::{
        crypto::{
            algorithms::{
                encryption::{
                    AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm,
                    SymmetricMode,
                },
                hashes::{Hash, Sha2Bits},
                KeyBits,
            },
            KeyUsage,
        },
        factory::SecurityModule,
    },
    tests::common::traits::setup_security_module,
};
use paste::paste;
use test_case::test_case;
use tracing::info;

// Static constants for common parameters
static RSA_KEY_BITS: KeyBits = KeyBits::Bits4096;
static ECDSA_CURVE: EccCurves = EccCurves::Curve25519;
static ECDH_CURVE: EccCurves = EccCurves::Curve25519;
static AES_MODE: SymmetricMode = SymmetricMode::Gcm;
static AES_KEY_BITS: KeyBits = KeyBits::Bits512;
static SHA2_BITS: Sha2Bits = Sha2Bits::Sha256;

static RSA_KEY_USAGE: &[KeyUsage] = &[
    KeyUsage::SignEncrypt,
    KeyUsage::ClientAuth,
    KeyUsage::SignEncrypt,
    KeyUsage::CreateX509,
];
static ECDSA_KEY_USAGE: &[KeyUsage] = &[KeyUsage::SignEncrypt, KeyUsage::ClientAuth];
static ECDH_KEY_USAGE: &[KeyUsage] = &[
    KeyUsage::SignEncrypt,
    KeyUsage::ClientAuth,
    KeyUsage::Decrypt,
];

static RSA_ENCRYPTION: AsymmetricEncryption = AsymmetricEncryption::Rsa(RSA_KEY_BITS);
static ECDSA_ENCRYPTION: AsymmetricEncryption =
    AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(ECDSA_CURVE));
static ECDH_ENCRYPTION: AsymmetricEncryption =
    AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(ECDH_CURVE));

#[cfg(feature = "linux")]
static LINUX_TPM: SecurityModule = SecurityModule::Tpm(TpmType::Linux);
#[cfg(feature = "win")]
static WINDOWS_TPM: SecurityModule = SecurityModule::Tpm(TpmType::Windows);
#[cfg(feature = "hsm")]
static NITROKEY_HSM: SecurityModule = SecurityModule::Hsm(HsmType::NitroKey);

/// The `key_test_cases!` macro generates test cases for creating and loading cryptographic keys.
/// It accepts a macro name and a list of test case definitions. Each test case includes the test
/// name, encryption type, key usage, and a set of features with corresponding modules, descriptions,
/// and suffixes.
///
/// # Syntax
/// ```rust
/// key_test_cases!(
///     $macro_name:ident,
///     $([$test_name:ident, $encryption:expr, $key_usage:expr, $([$feature:literal, $module:expr, $desc:literal, $suffix:literal]),+]),+
///     $(,)?
/// )
/// ```
///
/// # Parameters
/// - `$macro_name`: The name of the macro to invoke for each test case.
/// - `$test_name`: The identifier for the test case.
/// - `$encryption`: The encryption type used in the test.
/// - `$key_usage`: The key usage specifications.
/// - `$feature`: The feature gate for conditional compilation.
/// - `$module`: The module to be tested.
/// - `$desc`: A description of the test case.
/// - `$suffix`: A suffix for the test function name.
///
/// # Example Usage
/// ```rust
/// key_test_cases!(
///     create_key_test,
///     [
///         test_create_rsa_key_case,
///         RSA_ENCRYPTION,
///         RSA_KEY_USAGE,
///         ["linux", LINUX_TPM, "Linux TPM", "linux_rsa"],
///         ["win", WINDOWS_TPM, "Windows TPM", "win_rsa"],
///         ["hsm", NITROKEY_HSM, "NitroKey HSM", "hsm_rsa"]
///     ]
/// );
/// ```
macro_rules! key_test_cases {
    ($macro_name:ident, $([$test_name:ident, $encryption:expr, $key_usage:expr, $([$feature:literal, $module:expr, $desc:literal, $suffix:literal]),+]),+ $(,)?) => {
        $(
            $macro_name!(
                $test_name,
                $encryption,
                $key_usage,
                $([$feature, $module, $desc, $suffix]),+
            );
        )+
    };
}

/// The `create_key_test!` macro generates test functions for creating cryptographic keys. It
/// accepts the test name, encryption type, key usage, and a set of features with corresponding
/// modules, descriptions, and suffixes.
///
/// # Syntax
/// ```rust
/// create_key_test!(
///     $test_name:ident,
///     $encryption:expr,
///     $key_usage:expr,
///     $([$feature:literal, $module:expr, $desc:literal, $suffix:literal]),+
/// )
/// ```
///
/// # Parameters
/// - `$test_name`: The identifier for the test case.
/// - `$encryption`: The encryption type used in the test.
/// - `$key_usage`: The key usage specifications.
/// - `$feature`: The feature gate for conditional compilation.
/// - `$module`: The module to be tested.
/// - `$desc`: A description of the test case.
/// - `$suffix`: A suffix for the test function name.
///
/// # Example Usage
/// ```rust
/// create_key_test!(
///     test_create_rsa_key_case,
///     RSA_ENCRYPTION,
///     RSA_KEY_USAGE,
///     ["linux", LINUX_TPM, "Linux TPM", "linux_rsa"],
///     ["win", WINDOWS_TPM, "Windows TPM", "win_rsa"],
///     ["hsm", NITROKEY_HSM, "NitroKey HSM", "hsm_rsa"]
/// );
/// ```
///
/// # Generated Code
/// For each feature, this macro generates a test function that:
/// 1. Sets up the security module.
/// 2. Configures the TPM with the specified encryption and key usage.
/// 3. Initializes the module.
/// 4. Creates a key using the configuration.
macro_rules! create_key_test {
    ($test_name:ident, $encryption:expr, $key_usage:expr, $([$feature:literal, $module:expr, $desc:literal, $suffix:literal]),+) => {
        $(
            #[cfg(feature = $feature)]
            paste! {
                #[test_case($module ; $desc)]
                fn [<$test_name _ $suffix>](module: SecurityModule) {
                    let provider = setup_security_module(module);

                    let config = TpmConfig::new(
                        $encryption,
                        Some(BlockCiphers::Aes(AES_MODE, AES_KEY_BITS)),
                        Some(Hash::Sha2(SHA2_BITS)),
                        Some($key_usage.to_vec()),
                    );

                    let mut provider_lock = provider.lock().unwrap();

                    provider_lock
                        .initialize_module()
                        .expect("Failed to initialize module");

                    provider_lock
                        .create_key("test_key", config)
                        .expect("Failed to create key");
                }
            }
        )+
    };
}

/// The `load_key_test!` macro generates test functions for loading cryptographic keys. It accepts
/// the test name, encryption type, key usage, and a set of features with corresponding modules,
/// descriptions, and suffixes.
///
/// # Syntax
/// ```rust
/// load_key_test!(
///     $test_name:ident,
///     $encryption:expr,
///     $key_usage:expr,
///     $([$feature:literal, $module:expr, $desc:literal, $suffix:literal]),+
/// )
/// ```
///
/// # Parameters
/// - `$test_name`: The identifier for the test case.
/// - `$encryption`: The encryption type used in the test.
/// - `$key_usage`: The key usage specifications.
/// - `$feature`: The feature gate for conditional compilation.
/// - `$module`: The module to be tested.
/// - `$desc`: A description of the test case.
/// - `$suffix`: A suffix for the test function name.
///
/// # Example Usage
/// ```rust
/// load_key_test!(
///     test_load_rsa_key_case,
///     RSA_ENCRYPTION,
///     RSA_KEY_USAGE,
///     ["linux", LINUX_TPM, "Linux TPM", "linux_rsa"],
///     ["win", WINDOWS_TPM, "Windows TPM", "win_rsa"],
///     ["hsm", NITROKEY_HSM, "NitroKey HSM", "hsm_rsa"]
/// );
/// ```
///
/// # Generated Code
/// For each feature, this macro generates a test function that:
/// 1. Sets up the security module.
/// 2. Configures the TPM with the specified encryption and key usage.
/// 3. Logs the configuration.
/// 4. Initializes the module.
/// 5. Loads a key using the configuration.
macro_rules! load_key_test {
    ($test_name:ident, $encryption:expr, $key_usage:expr, $([$feature:literal, $module:expr, $desc:literal, $suffix:literal]),+) => {
        $(
            #[cfg(feature = $feature)]
            paste! {
                #[test_case($module ; $desc)]
                fn [<$test_name _ $suffix>](module: SecurityModule) {
                    let provider = setup_security_module(module);

                    let config = TpmConfig::new(
                        $encryption,
                        Some(BlockCiphers::Aes(AES_MODE, AES_KEY_BITS)),
                        Some(Hash::Sha2(SHA2_BITS)),
                        Some($key_usage.to_vec()),
                    );

                    info!("{:?}", config);

                    let mut provider_lock = provider.lock().unwrap();

                    provider_lock
                        .initialize_module()
                        .expect("Failed to initialize module");

                    provider_lock
                        .load_key("test_key", config)
                        .expect("Failed to load key");
                }
            }
        )+
    };
}

key_test_cases!(
    create_key_test,
    [
        test_create_rsa_key_case,
        Some(RSA_ENCRYPTION),
        RSA_KEY_USAGE,
        ["linux", LINUX_TPM.clone(), "Linux TPM", "linux_rsa"],
        ["win", WINDOWS_TPM.clone(), "Windows TPM", "win_rsa"],
        ["hsm", NITROKEY_HSM.clone(), "NitroKey HSM", "hsm_rsa"]
    ],
    [
        test_create_ecdsa_key_case,
        Some(ECDSA_ENCRYPTION),
        ECDSA_KEY_USAGE,
        ["linux", LINUX_TPM.clone(), "Linux TPM", "linux_ecdsa"],
        ["win", WINDOWS_TPM.clone(), "Windows TPM", "win_ecdsa"],
        ["hsm", NITROKEY_HSM.clone(), "NitroKey HSM", "hsm_ecdsa"]
    ],
    [
        test_create_ecdh_key_case,
        Some(ECDH_ENCRYPTION),
        ECDH_KEY_USAGE,
        ["linux", LINUX_TPM.clone(), "Linux TPM", "linux_ecdh"],
        ["win", WINDOWS_TPM.clone(), "Windows TPM", "win_ecdh"],
        ["hsm", NITROKEY_HSM.clone(), "NitroKey HSM", "hsm_ecdh"]
    ]
);

key_test_cases!(
    load_key_test,
    [
        test_load_rsa_key_case,
        Some(RSA_ENCRYPTION),
        RSA_KEY_USAGE,
        ["linux", LINUX_TPM.clone(), "Linux TPM", "linux_rsa"],
        ["win", WINDOWS_TPM.clone(), "Windows TPM", "win_rsa"],
        ["hsm", NITROKEY_HSM.clone(), "NitroKey HSM", "hsm_rsa"]
    ],
    [
        test_load_ecdsa_key_case,
        Some(ECDSA_ENCRYPTION),
        ECDSA_KEY_USAGE,
        ["linux", LINUX_TPM.clone(), "Linux TPM", "linux_ecdsa"],
        ["win", WINDOWS_TPM.clone(), "Windows TPM", "win_ecdsa"],
        ["hsm", NITROKEY_HSM.clone(), "NitroKey HSM", "hsm_ecdsa"]
    ],
    [
        test_load_ecdh_key_case,
        Some(ECDH_ENCRYPTION),
        ECDH_KEY_USAGE,
        ["linux", LINUX_TPM.clone(), "Linux TPM", "linux_ecdh"],
        ["win", WINDOWS_TPM.clone(), "Windows TPM", "win_ecdh"],
        ["hsm", NITROKEY_HSM.clone(), "NitroKey HSM", "hsm_ecdh"]
    ]
);

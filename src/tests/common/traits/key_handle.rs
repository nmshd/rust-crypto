use super::setup_security_module;
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{
                AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm, SymmetricMode,
            },
            hashes::{Hash, Sha2Bits},
            KeyBits,
        },
        KeyUsage,
    },
    factory::SecurityModule,
};
#[cfg(feature = "hsm")]
use crate::hsm::core::instance::HsmType;
#[cfg(feature = "tpm")]
use crate::tpm::{core::instance::TpmType, TpmConfig};
use async_std::task::block_on;
use paste::paste;
use test_case::test_case;

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

/// The `key_handle_test_cases!` macro generates test cases for handling cryptographic keys.
/// It accepts a macro name and a list of test case definitions. Each test case includes the feature,
/// suffix, description, module, encryption type, and key usage.
///
/// # Syntax
/// ```rust
/// key_handle_test_cases!(
///     $macro_name:ident,
///     $([$([$feature:literal, $suffix:ident, $desc:literal, $module:expr, $encryption:expr, $key_usage:expr]),+]),+
///     $(,)?
/// )
/// ```
///
/// # Parameters
/// - `$macro_name`: The name of the macro to invoke for each test case.
/// - `$feature`: The feature gate for conditional compilation.
/// - `$suffix`: A suffix for the test function name.
/// - `$desc`: A description of the test case.
/// - `$module`: The module to be tested.
/// - `$encryption`: The encryption type used in the test.
/// - `$key_usage`: The key usage specifications.
macro_rules! key_handle_test_cases {
    ($macro_name:ident, $([$([$feature:literal, $suffix:ident, $desc:literal, $module:expr, $encryption:expr, $key_usage:expr]),+]),+ $(,)?) => {
        $(
            $(
                $macro_name!(
                    $feature,
                    $suffix,
                    $desc,
                    $module,
                    $encryption,
                    $key_usage
                );
            )+
        )+
    };
}

/// The `sign_and_verify_test!` macro generates test functions for signing and verifying data.
/// It accepts the feature, suffix, description, module, encryption type, and key usage.
///
/// # Syntax
/// ```rust
/// sign_and_verify_test!(
///     $feature:literal,
///     $suffix:ident,
///     $desc:literal,
///     $module:expr,
///     $encryption:expr,
///     $key_usage:expr
/// )
/// ```
///
/// # Parameters
/// - `$feature`: The feature gate for conditional compilation.
/// - `$suffix`: A suffix for the test function name.
/// - `$desc`: A description of the test case.
/// - `$module`: The module to be tested.
/// - `$encryption`: The encryption type used in the test.
/// - `$key_usage`: The key usage specifications.
///
/// # Generated Code
/// This macro generates a test function that:
/// 1. Sets up the security module.
/// 2. Configures the TPM with the specified encryption and key usage.
/// 3. Initializes the module.
/// 4. Creates a key using the configuration.
/// 5. Signs some data.
/// 6. Verifies the signature of the data.
macro_rules! sign_and_verify_test {
    ($feature:literal, $suffix:ident, $desc:literal, $module:expr, $encryption:expr, $key_usage:expr) => {
        #[cfg(feature = $feature)]
        paste! {
            #[test_case($module ; $desc)]
            fn [<test_sign_and_verify_ $suffix>](module: SecurityModule) {
                // Initialize the security module
                let provider = block_on(setup_security_module(module));

                let config = TpmConfig::new(
                    $encryption,
                    Some(BlockCiphers::Aes(AES_MODE, AES_KEY_BITS)),
                    Some(Hash::Sha2(SHA2_BITS)),
                    Some($key_usage.to_vec()),
                );

                // Lock the provider and initialize the module
                {
                    let mut provider_lock = block_on(provider.lock());
                    let init_result = block_on(provider_lock.initialize_module());
                    init_result.expect("Failed to initialize module");
                }

                // Lock the provider and create a key
                {
                    let mut provider_lock = block_on(provider.lock());
                    let create_key_result = block_on(provider_lock.create_key("test_key", config));
                    create_key_result.expect("Failed to create key");
                }

                let data = b"Hello, World!";

                // Lock the provider and sign the data
                let signature = {
                    let provider_lock = block_on(provider.lock());
                    let sign_result = block_on(provider_lock.sign_data(data));
                    sign_result.expect("Failed to sign data")
                };

                // Lock the provider and verify the signature
                let verification = {
                    let provider_lock = block_on(provider.lock());
                    let verify_result = block_on(provider_lock.verify_signature(data, &signature));
                    verify_result.expect("Failed to verify signature")
                };

                assert!(verification, "Signature verification failed");
            }
        }
    };
}

/// The `encrypt_and_decrypt_test!` macro generates test functions for encrypting and decrypting data.
/// It accepts the feature, suffix, description, module, encryption type, and key usage.
///
/// # Syntax
/// ```rust
/// encrypt_and_decrypt_test!(
///     $feature:literal,
///     $suffix:ident,
///     $desc:literal,
///     $module:expr,
///     $encryption:expr,
///     $key_usage:expr
/// )
/// ```
///
/// # Parameters
/// - `$feature`: The feature gate for conditional compilation.
/// - `$suffix`: A suffix for the test function name.
/// - `$desc`: A description of the test case.
/// - `$module`: The module to be tested.
/// - `$encryption`: The encryption type used in the test.
/// - `$key_usage`: The key usage specifications.
///
/// # Generated Code
/// This macro generates a test function that:
/// 1. Sets up the security module.
/// 2. Configures the TPM with the specified encryption and key usage.
/// 3. Initializes the module.
/// 4. Creates a key using the configuration.
/// 5. Encrypts some data.
/// 6. Decrypts the data.
/// 7. Asserts that the decrypted data matches the original data.
macro_rules! encrypt_and_decrypt_test {
    ($feature:literal, $suffix:ident, $desc:literal, $module:expr, $encryption:expr, $key_usage:expr) => {
        #[cfg(feature = $feature)]
        paste! {
            #[test_case($module ; $desc)]
            fn [<test_encrypt_and_decrypt_ $suffix>](module: SecurityModule) {
                // Initialize the security module
                let provider = block_on(setup_security_module(module));

                let config = TpmConfig::new(
                    $encryption,
                    Some(BlockCiphers::Aes(AES_MODE, AES_KEY_BITS)),
                    Some(Hash::Sha2(SHA2_BITS)),
                    Some($key_usage.to_vec()),
                );

                // Lock the provider and initialize the module
                {
                    let mut provider_lock = block_on(provider.lock());
                    let init_result = block_on(provider_lock.initialize_module());
                    init_result.expect("Failed to initialize module");
                }

                // Lock the provider and create a key
                {
                    let mut provider_lock = block_on(provider.lock());
                    let create_key_result = block_on(provider_lock.create_key("test_key", config));
                    create_key_result.expect("Failed to create key");
                }

                let data = b"Hello, World!";

                // Lock the provider and encrypt the data
                let encrypted_data = {
                    let provider_lock = block_on(provider.lock());
                    let encrypt_result = block_on(provider_lock.encrypt_data(data));
                    encrypt_result.expect("Failed to encrypt data")
                };

                // Lock the provider and decrypt the data
                let decrypted_data = {
                    let provider_lock = block_on(provider.lock());
                    let decrypt_result = block_on(provider_lock.decrypt_data(&encrypted_data));
                    decrypt_result.expect("Failed to decrypt data")
                };

                // Assert that the decrypted data matches the original data
                assert_eq!(data, decrypted_data.as_slice());
            }
        }
    };
}

key_handle_test_cases!(
    sign_and_verify_test,
    [
        [
            "linux",
            linux_rsa,
            "Linux RSA Sign and Verify",
            LINUX_TPM.clone(),
            Some(RSA_ENCRYPTION),
            RSA_KEY_USAGE
        ],
        [
            "win",
            win_rsa,
            "Windows RSA Sign and Verify",
            WINDOWS_TPM.clone(),
            Some(RSA_ENCRYPTION),
            RSA_KEY_USAGE
        ],
        [
            "hsm",
            hsm_rsa,
            "HSM RSA Sign and Verify",
            NITROKEY_HSM.clone(),
            Some(RSA_ENCRYPTION),
            RSA_KEY_USAGE
        ]
    ],
    [
        [
            "linux",
            linux_ecdsa,
            "Linux ECDSA Sign and Verify",
            LINUX_TPM.clone(),
            Some(ECDSA_ENCRYPTION),
            ECDSA_KEY_USAGE
        ],
        [
            "win",
            win_ecdsa,
            "Windows ECDSA Sign and Verify",
            WINDOWS_TPM.clone(),
            Some(ECDSA_ENCRYPTION),
            ECDSA_KEY_USAGE
        ],
        [
            "hsm",
            hsm_ecdsa,
            "HSM ECDSA Sign and Verify",
            NITROKEY_HSM.clone(),
            Some(ECDSA_ENCRYPTION),
            ECDSA_KEY_USAGE
        ]
    ]
);

key_handle_test_cases!(
    encrypt_and_decrypt_test,
    [
        [
            "linux",
            linux_rsa,
            "Linux RSA Encrypt and Decrypt",
            LINUX_TPM.clone(),
            Some(RSA_ENCRYPTION),
            RSA_KEY_USAGE
        ],
        [
            "win",
            win_rsa,
            "Windows RSA Encrypt and Decrypt",
            WINDOWS_TPM.clone(),
            Some(RSA_ENCRYPTION),
            RSA_KEY_USAGE
        ],
        [
            "hsm",
            hsm_rsa,
            "HSM RSA Encrypt and Decrypt",
            NITROKEY_HSM.clone(),
            Some(RSA_ENCRYPTION),
            RSA_KEY_USAGE
        ]
    ],
    [
        [
            "linux",
            linux_ecdh,
            "Linux ECDH Encrypt and Decrypt",
            LINUX_TPM.clone(),
            Some(ECDH_ENCRYPTION),
            ECDH_KEY_USAGE
        ],
        [
            "win",
            win_ecdh,
            "Windows ECDH Encrypt and Decrypt",
            WINDOWS_TPM.clone(),
            Some(ECDH_ENCRYPTION),
            ECDH_KEY_USAGE
        ],
        [
            "hsm",
            hsm_ecdh,
            "HSM ECDH Encrypt and Decrypt",
            NITROKEY_HSM.clone(),
            Some(ECDH_ENCRYPTION),
            ECDH_KEY_USAGE
        ]
    ]
);

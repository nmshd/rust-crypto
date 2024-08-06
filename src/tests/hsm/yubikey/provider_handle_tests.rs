/// # Test Cases for YubiKeyProvider
///
/// The `YubiKeyProvider` module facilitates the creation and loading of cryptographic keys
/// on a YubiKey device. This module contains several test cases to ensure the functionality
/// of key creation and loading for different key types and sizes.
///
/// ## Test Cases
///
/// - `test_create_rsa_key_1024`: Tests the creation of a 1024-bit RSA key pair on the YubiKey device.
/// - `test_create_rsa_key_2048`: Tests the creation of a 2048-bit RSA key pair on the YubiKey device.
/// - `test_create_ecc_key_256`: Tests the creation of a 256-bit ECC key pair on the YubiKey device.
/// - `test_create_ecc_key_384`: Tests the creation of a 384-bit ECC key pair on the YubiKey device.
/// - `test_load_rsa_key`: Tests the loading of an RSA key pair from the YubiKey device.
/// - `test_load_ecc_key`: Tests the loading of an ECC key pair from the YubiKey device.
///
/// ## Test Procedures
///
/// Each test case follows a similar procedure:
///
/// 1. **Initialization**: Initializes the `YubiKeyProvider` with the necessary parameters, such as
///    the key ID and configuration.
/// 2. **Module Initialization**: Initializes the HSM module on the YubiKey device.
/// 3. **Key Creation/Loading**: Either creates a new key pair or loads an existing key pair
///    based on the test case requirements.
///
/// ## Test Parameters
///
/// Each test case specifies the key type, size, and usage:
///
/// - **RSA Keys**: Test cases for RSA keys specify either 1024-bit or 2048-bit key sizes
///   with key usage for signing and encryption.
/// - **ECC Keys**: Test cases for ECC keys specify either 256-bit or 384-bit key sizes
///   with key usage for signing and encryption.
///
/// ## Test Assumptions
///
/// These test cases assume that a YubiKey device is connected and properly configured for
/// cryptographic operations. They also assume that the YubiKey device is accessible via
/// the system's USB interface.
///
/// ## Expected Behavior
///
/// The expected behavior for each test case is successful key creation or loading without
/// encountering any errors. Any failures during key creation or loading are considered test
/// failures and will be reported accordingly.
///
/// Please use **cargo test --features yubi -- --test-threads=1** for successful testing due to parallelization issues
#[allow(unused_imports)]
use crate::common::{
    crypto::{
        algorithms::{
            encryption::{AsymmetricEncryption, BlockCiphers, EccCurves, EccSchemeAlgorithm},
            hashes::Hash,
            KeyBits,
        },
        KeyUsage,
    },
    traits::module_provider::Provider,
};
use crate::hsm::yubikey::YubiKeyProvider;
use crate::hsm::HsmProviderConfig;

// Tests for creating 1024-bit RSA keys
#[cfg(feature = "yubi")]
#[test]
fn test_create_rsa_key_1024() {
    let key_id = "test_rsa_key_1024";
    let mut provider = YubiKeyProvider::new(key_id.to_string());
    let config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));

    //initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    //generate RSA-keypair
    provider
        .create_key(key_id, config)
        .expect("Failed to create RSA key");
}

// Tests for creating 2048-bit RSA keys
#[cfg(feature = "yubi")]
#[test]
fn test_create_rsa_key_2048() {
    let key_id = "test_rsa_key_2048";
    let mut provider: YubiKeyProvider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits2048));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // generate RSA-keypair
    provider
        .create_key(key_id, config)
        .expect("Failed to create RSA key");
}

//Tests for creating 256-bit ECC keys
#[cfg(feature = "yubi")]
#[test]
fn test_create_ecc_key_256() {
    let key_id = "test_ecc_key_256";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
        EccCurves::P256,
    )));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // generate ECC-keypair
    provider
        .create_key(key_id, config)
        .expect("Failed to create ECC key");
}

// Tests for creating 384-bit ECC keys
#[cfg(feature = "yubi")]
#[test]
fn test_create_ecc_key_384() {
    let key_id = "test_ecc_key_384";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
        EccCurves::P384,
    )));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // generate ECC-keypair
    provider
        .create_key(key_id, config)
        .expect("Failed to create ECC key");
}

// Test for loading RSA keys
#[cfg(feature = "yubi")]
#[test]
fn test_load_rsa_key_1024() {
    let key_id = "test_rsa_key_1024";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // load RSA-key
    provider
        .load_key(key_id, config)
        .expect("Failed to load RSA key");
}

// Test for loading RSA keys
#[cfg(feature = "yubi")]
#[test]
fn test_load_rsa_key_2048() {
    let key_id = "test_rsa_key_2048";
    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Rsa(KeyBits::Bits1024));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // load RSA-key
    provider
        .load_key(key_id, config)
        .expect("Failed to load RSA key");
}

// Test to load an ECC key
#[cfg(feature = "yubi")]
#[test]
fn test_load_ecc_key_256() {
    let key_id = "test_ecc_key_256";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
        EccCurves::P256,
    )));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // load ECC-key
    provider
        .load_key(key_id, config)
        .expect("Failed to load ECC key");
}

// Test to load an ECC key
#[cfg(feature = "yubi")]
#[test]
fn test_load_ecc_key_384() {
    let key_id = "test_ecc_key_384";

    let mut provider = YubiKeyProvider::new(key_id.to_string());

    let config = HsmProviderConfig::new(AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(
        EccCurves::P256,
    )));

    // initialize HSM-module
    provider
        .initialize_module()
        .expect("Failed to initialize module");

    // load ECC-key
    provider
        .load_key(key_id, config)
        .expect("Failed to load ECC key");
}

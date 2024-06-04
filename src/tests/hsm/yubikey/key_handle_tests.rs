/// # Test Cases for Cryptographic Operations
///
/// The purpose of this module is to provide comprehensive tests for cryptographic operations
/// within the system, specifically focusing on signing and verifying data using RSA and ECC keys.
/// These tests ensure the integrity and reliability of cryptographic operations, which are crucial
/// for maintaining the security of the system's data and communications.
///
/// ## Test Cases
///
/// - `test_sign_and_verify_rsa_1024`: Tests signing and verifying data with a 1024-bit RSA key.
/// - `test_sign_and_verify_rsa_2048`: Tests signing and verifying data with a 2048-bit RSA key.
/// - `test_sign_and_verify_ecc_256`: Tests signing and verifying data with a 256-bit ECC key.
/// - `test_sign_and_verify_ecc_384`: Tests signing and verifying data with a 384-bit ECC key.
///
/// ## Test Procedures
///
/// Each test case follows a similar procedure:
///
/// 1. **Initialization**: Initializes the `YubiKeyProvider` with the necessary parameters, such as
///    the key ID and configuration.
/// 2. **Module Initialization**: Initializes the HSM module on the YubiKey device.
/// 3. **Key Creation**: Creates a new key pair based on the test case requirements.
/// 4. **Signing**: Signs a predefined data string.
/// 5. **Verification**: Verifies the signature of the signed data.
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
/// The expected behavior for each test case is successful key creation, signing, and verification
/// without encountering any errors. Any failures during these operations are considered test
/// failures and will be reported accordingly.
///
/// Please use **cargo test --features yubi -- --test-threads=1** for successful testing due to parallelization issues.
#[cfg(test)]
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
    traits::{key_handle::KeyHandle, module_provider::Provider},
};

// Import YubiKeyProvider and HsmProviderConfig for HSM operations
use crate::hsm::{yubikey::YubiKeyProvider, HsmProviderConfig};
// The following tests cover different cryptographic scenarios, ensuring the robustness and
// compatibility of the system across various configurations and key sizes.

//Test for signing and verifying RSA data with 1024-bit key
#[test]
fn test_sign_and_verify_rsa_1024() {
    // Initialization of YubiKeyProvider and configuration of HsmProviderConfig
    // omitted for brevity; please refer to the individual test implementations
    let mut provider = YubiKeyProvider::new("test_sv_1024".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits1024),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_sv_1024", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

// Test for signing and verifying RSA data with a 2048-bit key
#[test]
fn test_sign_and_verify_rsa_2048() {
    let mut provider = YubiKeyProvider::new("test_sv_2048".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits2048),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_sv_2048", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

// Test for signing and verifying ECC data with a 256-bit key
#[test]
fn test_sign_and_verify_ecc_256() {
    let mut provider = YubiKeyProvider::new("test_ecc_256".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256)),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecc_256", config)
        .expect("Failed to create ECC key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

// Test for signing and verifying ECC data with a 384-bit key
#[test]
fn test_sign_and_verify_ecc_384() {
    let mut provider = YubiKeyProvider::new("test_ecc_384".to_string());

    let config = HsmProviderConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P384)),
        vec![KeyUsage::SignEncrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecc_384", config)
        .expect("Failed to create ECC key");

    let data = b"Hello, World!";
    let signature = provider.sign_data(data).expect("Failed to sign data");

    assert!(provider.verify_signature(data, &signature).unwrap());
}

/*
/// The following tests, `test_encrypt_and_decrypt_rsa` and `test_encrypt_and_decrypt_ecdh`,
/// are currently commented out as they are placeholders for future implementations
/// involving encryption and decryption operations. These tests will further expand the
/// test coverage to ensure the complete functionality of the cryptographic operations
/// provided by the system.

#[test]
fn test_encrypt_and_decrypt_rsa() {
    let mut provider = TpmProvider::new("test_rsa_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Rsa(KeyBits::Bits4096),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_rsa_key", config)
        .expect("Failed to create RSA key");

    let data = b"Hello, World!";
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}

#[test]
fn test_encrypt_and_decrypt_ecdh() {
    let mut provider = TpmProvider::new("test_ecdh_key".to_string());

    let config = TpmConfig::new(
        AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDh(EccCurves::Curve25519)),
        BlockCiphers::Aes(SymmetricMode::Gcm, KeyBits::Bits512),
        Hash::Sha2(Sha2Bits::Sha256),
        vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt],
    );

    provider
        .initialize_module()
        .expect("Failed to initialize module");
    provider
        .create_key("test_ecdh_key", config)
        .expect("Failed to create ECDH key");

    let data = b"Hello, World!";
    let encrypted_data = provider.encrypt_data(data).expect("Failed to encrypt data");
    let decrypted_data = provider
        .decrypt_data(&encrypted_data)
        .expect("Failed to decrypt data");

    assert_eq!(data, decrypted_data.as_slice());
}
*/

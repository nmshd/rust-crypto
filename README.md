# Work in Progress

Not fully implemented yet

# Crypto Layer

The Crypto Layer is a comprehensive and flexible cryptographic library designed to provide a unified interface for various cryptographic operations and algorithms. It offers a wide range of functionalities, including encryption, decryption, signing, signature verification, and hashing, while supporting both symmetric and asymmetric cryptography.

## Features

- **Encryption Algorithms**: Supports a variety of encryption algorithms, including:

  - Asymmetric Encryption: RSA, ECC (Elliptic Curve Cryptography) with various curve types (P-256, P-384, P-521, secp256k1, Brainpool curves, Curve25519, Curve448, FRP256v1)
  - Symmetric Block Ciphers: AES (with multiple modes like GCM, CCM, ECB, CBC, CFB, OFB, CTR), Triple DES (two-key and three-key configurations), DES, RC2, Camellia
  - Stream Ciphers: RC4, ChaCha20

- **Hashing Algorithms**: Supports a wide range of hashing algorithms, including:

  - SHA-1, SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
  - SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
  - MD2, MD4, MD5, RIPEMD-160

- **Key Management**: Provides a unified interface for creating, loading, and managing cryptographic keys, supporting various key usages and algorithms.

- **Cross-Platform Support**: Designed to work seamlessly across multiple platforms, including Linux and Windows, with platform-specific implementations for key handling and security module integration.

- **Security Module Integration**: Integrates with Hardware Security Modules (HSMs) and Trusted Platform Modules (TPMs) for secure key storage and cryptographic operations, ensuring enhanced security and compliance with industry standards.

- **Extensibility**: The modular design of the Crypto Layer allows for easy extension and integration of additional cryptographic algorithms and security modules in the future.

## Usage

The Crypto Layer provides a comprehensive set of interfaces and enums for working with cryptographic operations and algorithms. Here's a brief overview of the main components:

### Encryption Algorithms

The `encryption` module defines enums for various encryption algorithms, including:

- `AsymmetricEncryption`: Represents asymmetric encryption algorithms like RSA and ECC.
- `BlockCiphers`: Represents symmetric block cipher algorithms like AES, Triple DES, DES, RC2, and Camellia.
- `StreamCiphers`: Represents stream cipher algorithms like RC4 and ChaCha20.

### Hashing Algorithms

The `hashes` module defines the `Hash` enum, which represents various hashing algorithms like SHA-1, SHA-2, SHA-3, MD2, MD4, MD5, and RIPEMD-160.

### Key Management

The `key_handle` module provides the `KeyHandle` trait, which defines a common interface for cryptographic key operations like signing, decryption, encryption, and signature verification. The `GenericKeyHandle` enum represents a platform-agnostic key handle that can be used on both Linux and Windows platforms.

### Security Module Integration

The `module_provider` module defines the `Provider` trait, which encapsulates operations related to cryptographic processing and key management. This trait is designed to be implemented by security modules, ensuring a unified approach to interacting with different types of security modules.

The `factory` module provides the `SecModules` struct, which serves as a namespace for managing and accessing security module instances. It includes methods for retrieving or creating instances of security modules based on their type (HSM or TPM).

### Error Handling

The `error` module defines the `SecurityModuleError` enum, which represents various types of errors that can occur within a security module, including errors originating from HSMs, TPMs, or during cryptographic operations like signing, decryption, encryption, and signature verification.

### Usage Examples

Here are some usage examples based on the Windows TPM handler implementation:

#### Creating a TPM Provider

```rust
use crypto_layer::factory::{SecModules, SecurityModule};
use crypto_layer::tpm::core::instance::TpmType;

let key_id = "my_key_id".to_string();
let tpm_provider = SecModules::get_instances(key_id, SecurityModule::Tpm(TpmType::default()))
    .expect("Failed to create TPM provider");
```

#### Initializing the TPM Module

```rust
use crypto_layer::common::error::SecurityModuleError;

match tpm_provider.lock().unwrap().initialize_module() {
    Ok(()) => println!("TPM module initialized successfully"),
    Err(e) => println!("Failed to initialize TPM module: {:?}", e),
}
```

#### Creating a Key

```rust
use crypto_layer::common::crypto::algorithms::{
    encryption::{AsymmetricEncryption, BlockCiphers},
    hashes::Hash,
};
use crypto_layer::common::KeyUsage;

let key_algorithm = AsymmetricEncryption::Ecc(EccSchemeAlgorithm::EcDsa(EccCurves::P256));
let sym_algorithm = Some(BlockCiphers::Aes(SymmetricMode::Cbc, KeyBits::Bits256));
let hash = Some(Hash::Sha2(Sha2Bits::Sha256));
let key_usages = vec![KeyUsage::SignEncrypt, KeyUsage::Decrypt];

match tpm_provider.lock().unwrap().create_key(
    "my_key_id",
    key_algorithm,
    sym_algorithm,
    hash,
    key_usages,
) {
    Ok(()) => println!("Key created successfully"),
    Err(e) => println!("Failed to create key: {:?}", e),
}
```

#### Signing Data

```rust
let data = b"Hello, world!";

match tpm_provider.lock().unwrap().sign_data(data) {
    Ok(signature) => println!("Signature: {:?}", signature),
    Err(e) => println!("Failed to sign data: {:?}", e),
}
```

#### Verifying Signature

```rust
let data = b"Hello, world!";
let signature = // ... obtained signature ...

match tpm_provider.lock().unwrap().verify_signature(data, &signature) {
    Ok(valid) => {
        if valid {
            println!("Signature is valid");
        } else {
            println!("Signature is invalid");
        }
    }
    Err(e) => println!("Failed to verify signature: {:?}", e),
}
```

These examples demonstrate how to use the Windows TPM handler implementation to perform various cryptographic operations using the Crypto Layer.

## Installation

The Crypto Layer is distributed as a Rust crate and can be included in your project by adding the following line to your `Cargo.toml` file:

```toml
[dependencies]
crypto-layer = "0.1.0"
```

## Contributing

Contributions to the Crypto Layer are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the project's GitHub repository.

## License

The Crypto Layer is released under the [MIT License](LICENSE).

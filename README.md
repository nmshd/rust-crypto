<div align="center">

# Crypto Layer

</div>

> [!WARNING]
> Work in Progress

Crypto Layer is a comprehensive and flexible cryptographic library designed to provide a unified interface for various cryptographic operations and algorithms.
It offers a wide range of functionalities, including encryption, decryption, signing, signature verification, and hashing, while supporting both symmetric and asymmetric cryptography.


## Features

- **Encryption Algorithms**: Supports a variety of encryption algorithms, including:

  - Asymmetric Encryption: RSA, ECC (Elliptic Curve Cryptography) with various curve types (P-256, P-384, P-521, secp256k1, Brainpool curves, Curve25519, Curve448, FRP256v1)
  - Symmetric Block Ciphers: AES (GCM, CBC)
  - Stream Ciphers: ChaCha20, XChaCha20


- **Hashing Algorithms**: Supports a wide range of hashing algorithms, including:

  - SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
  - SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)


- **Key Management**: Provides a unified interface for creating, loading, and managing cryptographic keys, supporting various key usages and algorithms.

- **Cross-Platform Support**: Designed to work seamlessly across multiple platforms, including Android, Apple, Linux and Windows, with platform-specific implementations for key handling and security module integration.

- **Security Module Integration**: Integrates with Hardware Security Modules (HSMs) and Trusted Platform Modules (TPMs) for secure key storage and cryptographic operations, ensuring enhanced security and compliance with industry standards.

- **Extensibility**: The modular design of the Crypto Layer allows for easy extension and integration of additional cryptographic algorithms and security modules in the future.

## Design

### Overview

- **Providers** are interfaces to native implemented secure storages like TPM, HSM, NKS and the fallback software provider.
- **Key Pair Handles** are interfaces for interacting and operating with a native key pair (P256).
- **Key Handles** are interfaces for interacting and operating with a native symmetric keys (AES).
- **DH Exchanges** are interfaces for executing a DH key exchange.

```mermaid
%% https://mermaid.js.org/syntax/classDiagram.html
classDiagram
    direction LR

    Provider "1" --> "0..*" KeyHandle : manages
    Provider "1" --> "0..*" KeyPairHandle : manages
    Provider "1" --> "0..*" DHExchange : creates ephemeral
    KeyPairHandle "1" --> "1" DHExchange : creates
    DHExchange "1" --> "1" KeyHandle : results in

    class Provider {
        <<Interface>>
    }
    note for Provider "is created by factory methods"
    class KeyHandle {
        <<Interface>>  
    }
    class KeyPairHandle {
        <<Interface>>  
    }
    class DHExchange {
        <<Interface>> 
    }
```

## Usage

### Usage Rust Crate

Add the library via `cargo` to your project:
```
cargo add https://github.com/nmshd/rust-crypto
```

#### Examples

Examples for the rust crate can be found in the [example folder](./examples/).


### [Usage Flutter Plugin](./flutter_plugin/README.md)

### [Example Flutter App integration](./flutter_app/README.md)

### [Usage NodeJS Plugin](./node-plugin/README.md)

## Contributing

Contributions to the Crypto Layer are welcome!
If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the project's GitHub repository.


## License

The library Crypto Layer is released under the [MIT License](LICENSE).

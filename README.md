# Work in Progress

Not fully implemented yet

# Example Flutter App integration

This repository additionally contains a Flutter native plugin and an example Flutter app to test the Crypto Abstraction Layer, currently only supporting Android.

To run this App, the following tools are reqiuired:
- Rust compiler
- Rust aarch64-linux-android and armv7-linux-androideabi toolchains
- cargo-ndk
- Android Debug Bridge (adb)
- Flutter
- Android SDK
- Android NDK

## Installation
```
# rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# toolchains
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android

# cargo-ndk
cargo install cargo-ndk
```

Addidtionally install Flutter and either install Android Studio or Download the Android SDK
Now you can install the NDK with:
```
sdkmanager ndk-bundle
```

## Running the App

Get the id of the connected Android device with `flutter devices`, then run the App in debug mode:

```
cd flutter_app
flutter run -d $DEVICEID
```
This should compile the Rust code and the plugin and start the App on the device.

As Android Emulators don't contain a Secure Element, the App was only tested on real devices.

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

- **Cross-Platform Support**: Designed to work seamlessly across multiple platforms, including Android, Apple, Linux and Windows, with platform-specific implementations for key handling and security module integration.

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

### Usage Examples

Here are some usage examples using the Android provider in both Rust and Dart (using the flutter plugin)

#### Creating a TPM Provider

Rust:

```rust
use crypto_layer::common::factory;
use crypto_layer::common::config::ProviderImplConfig;

let java_vm = ...
let android_config = ProviderImplConfig::Android { vm: java_vm };

let provider = factory::create_provider_from_name("AndroidProvider".to_owned(), android_config)
```

Dart:

```dart
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart';

var implConf = await getAndroidConfig();
var provider = await createProviderFromName(name: "AndroidProvider", implConf: implConf);
```

#### Creating a Keypair

Rust:

```rust
use crypto_layer::common::config::KeyPairSpec;
use crypto_layer::common::crypto::algorithms::encryption::AsymmetricKeySpec;
use crypto_layer::common::crypto::algorithms::hashes::{CryptoHash, Sha2Bits};
use crypto_layer::common::crypto::algorithms::KeyBits;

let key_pair_spec = KeyPairSpec {
    asym_spec: AsymmetricKeySpec::Rsa(KeyBits::Bits2048),
    cipher: None,
    signing_hash: CryptoHash::Sha2(Sha2Bits::Sha256),
}

let key_pair = provider.create_key_pair(key_pair_spec)?;
```

Dart:

```dart
var spec = cal.KeyPairSpec(
    asymSpec: cal.AsymmetricKeySpec.rsa(cal.KeyBits.bits2048),
    signingHash: const cal.CryptoHash.sha2(cal.Sha2Bits.sha256));
var keyPair = await provider.createKeyPair(spec: spec);
```

#### Signing Data

Rust:

```rust
let data = b"Hello, world!";

match key_pair.sign_data(data) {
    Ok(signature) => println!("Signature: {:?}", signature),
    Err(e) => println!("Failed to sign data: {:?}", e),
}
```

Dart:

```dart
var data = ...

// Errors are thrown as Exceptions
var signature = await keyPair.signData(data)
```

#### Verifying Signature

Rust:

```rust
let data = b"Hello, world!";
let signature = // ... obtained signature ...

match key_pair.verify_signature(data, &signature) {
    Ok(true) => println!("Signature is valid"),
    Ok(false) => println!("Signature is invalid"),
    Err(e) => println!("Failed to verify signature: {:?}", e),
}
```

Dart:

```dart
var data = ...;
var signature = ...;

if (await keyPair.verifySignature(data, signature))
    print("Signature is valid");
else
    print("Signature is invalid");
```

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

// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.5.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../../../../frb_generated.dart';
import '../algorithms.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:freezed_annotation/freezed_annotation.dart' hide protected;
part 'encryption.freezed.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `eq`, `eq`, `eq`, `eq`, `eq`, `eq`, `eq`, `eq`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `hash`, `hash`, `hash`, `hash`, `hash`, `hash`, `hash`, `hash`

@freezed
sealed class AsymmetricKeySpec with _$AsymmetricKeySpec {
  const AsymmetricKeySpec._();

  /// RSA encryption with selectable key sizes.
  ///
  /// Allows specifying the key size for RSA encryption through the `KeyBits` enum,
  /// supporting various standard key lengths for different security needs. RSA is widely used
  /// for secure data transmission and is known for its simplicity and strong security properties,
  /// provided a sufficiently large key size is used.
  const factory AsymmetricKeySpec.rsa(
    KeyBits field0,
  ) = AsymmetricKeySpec_Rsa;

  /// Represents Elliptic Curve Cryptography (ECC) encryption.
  ///
  /// ECC offers encryption methods based on elliptic curves over finite fields,
  /// potentially including various algorithms and curves such as P-256, P-384, and others.
  /// ECC is known for providing the same level of security as RSA but with smaller key sizes,
  /// leading to faster computations and lower power consumption.
  const factory AsymmetricKeySpec.ecc({
    required EccSigningScheme scheme,
    required EccCurve curve,
  }) = AsymmetricKeySpec_Ecc;
}

/// Specifies ChaCha20 Variant.
/// flutter_rust_bridge:non_opaque
enum ChCha20Mode {
  chaCha20Poly1305,
  xChaCha20Poly1305,
  ;
}

@freezed
sealed class Cipher with _$Cipher {
  const Cipher._();

  /// AES (Advanced Encryption Standard) block cipher with selectable key sizes and modes.
  const factory Cipher.aes(
    SymmetricMode field0,
    KeyBits field1,
  ) = Cipher_Aes;

  /// Triple DES block cipher, either in two-key or three-key configurations.
  const factory Cipher.tripleDes(
    TripleDesNumKeys field0,
  ) = Cipher_TripleDes;

  /// DES (Data Encryption Standard) block cipher, now considered insecure for many applications.
  const factory Cipher.des() = Cipher_Des;

  /// RC2 block cipher with selectable key sizes.
  const factory Cipher.rc2(
    Rc2KeyBits field0,
  ) = Cipher_Rc2;

  /// Camellia block cipher with selectable key sizes.
  const factory Cipher.camellia(
    SymmetricMode field0,
    KeyBits field1,
  ) = Cipher_Camellia;

  /// RC4 stream cipher.
  ///
  /// Once widely used, RC4 is now considered insecure due to vulnerabilities that have
  /// been discovered over time. It is included here for legacy support and should not
  /// be used for new applications requiring secure encryption.
  const factory Cipher.rc4() = Cipher_Rc4;

  /// ChaCha20 stream cipher.
  ///
  /// Provides strong security and high performance, making it suitable for a wide
  /// range of modern applications. ChaCha20 is recommended for use when a secure and
  /// efficient stream cipher is required.
  const factory Cipher.chacha20(
    ChCha20Mode field0,
  ) = Cipher_Chacha20;

  static Future<Cipher> default_() => RustLib.instance.api
      .cryptoLayerCommonCryptoAlgorithmsEncryptionCipherDefault();
}

/// Specifies the curve types for Elliptic Curve Digital Signature Algorithm (ECDSA).
///
/// Lists the supported elliptic curve specifications for ECDSA, affecting security and performance.
/// Includes both NIST P-curves and others like secp256k1 and Brainpool curves.
///
/// # Examples
///
/// Selecting an ECDSA curve:
///
/// ```
/// use crypto_layer::common::crypto::algorithms::encryption::EccCurve;
///
/// fn main() {
///     let curve_type = EccCurve::P256;
/// }
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility.
/// flutter_rust_bridge:non_opaque
enum EccCurve {
  /// NIST P-256 curve.
  p256,

  /// NIST P-384 curve.
  p384,

  /// NIST P-521 curve.
  p521,

  /// secp256k1 curve, commonly used in blockchain technologies.
  secp256K1,

  /// Brainpool P256r1 curve.
  brainpoolP256R1,

  /// Brainpool P384r1 curve.
  brainpoolP384R1,

  /// Brainpool P512r1 curve.
  brainpoolP512R1,

  /// Brainpool P638 curve.
  brainpoolP638,

  /// Curve25519, popular for its security and performance.
  curve25519,

  /// Curve448, known for high security and efficiency.
  curve448,

  /// FRP256v1, a French curve providing strong security and performance.
  frp256V1,
  ;
}

/// flutter_rust_bridge:non_opaque
enum EccSigningScheme {
  /// ECDSA: Elliptic Curve Digital Signature Algorithm.
  ecDsa,

  /// ECDAA: Elliptic Curve Direct Anonymous Attestation.
  ecDaa,

  /// EC-Schnorr: A Schnorr signature scheme variant using elliptic curves.
  ecSchnorr,
  ;
}

/// Specifies the key sizes for the RC2 block cipher.
///
/// This enum lists the supported key sizes for RC2, such as 40, 64, and 128 bits.
/// The selection of key size impacts the security and compatibility of the encryption process.
///
/// # Examples
///
/// Selecting an RC2 key size of 128 bits:
///
/// ```rust
/// use crypto_layer::common::crypto::algorithms::encryption:: Rc2KeyBits;
///
/// fn main() {
///     let key_size = Rc2KeyBits::Rc2_128;
/// }
/// ```
///
/// # Note
///
/// Marked with `#[repr(C)]` to ensure compatibility with C-based environments.
/// flutter_rust_bridge:non_opaque
enum Rc2KeyBits {
  /// RC2 with a 40-bit key.
  rc240,

  /// RC2 with a 64-bit key.
  rc264,

  /// RC2 with a 128-bit key, offering the highest level of security among the options.
  rc2128,
  ;
}

/// Specifies the modes of operation for symmetric block ciphers.
///
/// This enum lists the supported modes of operation, such as GCM, CCM, ECB, CBC, CFB, OFB, and CTR.
/// These modes determine how block ciphers process plaintext and ciphertext, affecting security and performance characteristics.
///
/// # Examples
///
/// Selecting AES in GCM mode:
///
/// ```rust
/// use crypto_layer::common::crypto::algorithms::encryption::SymmetricMode;
///
/// fn main() {
///     let mode = SymmetricMode::Gcm;
/// }
/// ```
///
/// # Note
///
/// `#[repr(C)]` attribute is used for C compatibility.
/// flutter_rust_bridge:non_opaque
enum SymmetricMode {
  /// AES in Galois/Counter Mode (GCM) with selectable key sizes.
  /// GCM is preferred for its performance and security, providing both encryption and authentication.
  gcm,

  /// AES in Counter with CBC-MAC (CCM) mode with selectable key sizes.
  /// CCM combines counter mode encryption with CBC-MAC authentication, suitable for constrained environments.
  ccm,

  /// AES in Electronic Codebook (ECB) mode.
  /// ECB encrypts each block of data independently. Due to its deterministic nature, it's considered insecure for most uses.
  ecb,

  /// AES in Cipher Block Chaining (CBC) mode.
  /// CBC mode introduces dependencies between blocks for better security but requires proper IV management.
  cbc,

  /// AES in Cipher Feedback (CFB) mode.
  /// CFB mode turns AES into a stream cipher, allowing for encryption of partial blocks. It's useful for streaming data.
  cfb,

  /// AES in Output Feedback (OFB) mode.
  /// OFB mode also converts AES into a stream cipher but generates keystream blocks independently of the plaintext.
  ofb,

  /// AES in Counter (CTR) mode.
  /// CTR mode encrypts a sequence of counters, offering high throughput and parallelization capabilities.
  ctr,
  ;

  static Future<SymmetricMode> default_() => RustLib.instance.api
      .cryptoLayerCommonCryptoAlgorithmsEncryptionSymmetricModeDefault();
}

/// Specifies the number of keys used in Triple DES configurations.
///
/// This enum provides options for two-key (Ede2) and three-key (Ede3) Triple DES configurations.
/// The choice between two-key and three-key configurations affects the security level and performance of the encryption process.
///
/// # Examples
///
/// Selecting a Triple DES configuration with three keys:
///
/// ```rust
/// use crypto_layer::common::crypto::algorithms::encryption::TripleDesNumKeys;
///
/// fn main() {
///     let des_config = TripleDesNumKeys::Tdes3;
/// }
/// ```
///
/// # Note
///
/// Uses `#[repr(C)]` for C language compatibility.
/// flutter_rust_bridge:non_opaque
enum TripleDesNumKeys {
  /// Two-key Triple DES, using two different keys for encryption.
  tdes2,

  /// Three-key Triple DES, providing enhanced security with three different keys.
  tdes3,
  ;
}

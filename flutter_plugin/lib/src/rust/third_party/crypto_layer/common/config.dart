// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.5.1.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../../frb_generated.dart';
import 'crypto/algorithms.dart';
import 'crypto/algorithms/encryption.dart';
import 'crypto/algorithms/hashes.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `assert_receiver_is_total_eq`, `clone`, `clone`, `clone`, `clone`, `clone`, `cmp`, `eq`, `fmt`, `fmt`, `fmt`, `fmt`, `partial_cmp`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<ProviderImplConfig>>
abstract class ProviderImplConfig implements RustOpaqueInterface {}

class KeyPairSpec {
  final AsymmetricKeySpec asymSpec;
  final Cipher? cipher;
  final CryptoHash signingHash;

  const KeyPairSpec({
    required this.asymSpec,
    this.cipher,
    required this.signingHash,
  });

  @override
  int get hashCode =>
      asymSpec.hashCode ^ cipher.hashCode ^ signingHash.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeyPairSpec &&
          runtimeType == other.runtimeType &&
          asymSpec == other.asymSpec &&
          cipher == other.cipher &&
          signingHash == other.signingHash;
}

class KeySpec {
  final Cipher cipher;
  final CryptoHash signingHash;

  const KeySpec({
    required this.cipher,
    required this.signingHash,
  });

  @override
  int get hashCode => cipher.hashCode ^ signingHash.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeySpec &&
          runtimeType == other.runtimeType &&
          cipher == other.cipher &&
          signingHash == other.signingHash;
}

class ProviderConfig {
  final SecurityLevel maxSecurityLevel;
  final SecurityLevel minSecurityLevel;
  final Set<Cipher> supportedCiphers;
  final Set<CryptoHash> supportedHashes;
  final Set<AsymmetricKeySpec> supportedAsymSpec;

  const ProviderConfig({
    required this.maxSecurityLevel,
    required this.minSecurityLevel,
    required this.supportedCiphers,
    required this.supportedHashes,
    required this.supportedAsymSpec,
  });

  @override
  int get hashCode =>
      maxSecurityLevel.hashCode ^
      minSecurityLevel.hashCode ^
      supportedCiphers.hashCode ^
      supportedHashes.hashCode ^
      supportedAsymSpec.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ProviderConfig &&
          runtimeType == other.runtimeType &&
          maxSecurityLevel == other.maxSecurityLevel &&
          minSecurityLevel == other.minSecurityLevel &&
          supportedCiphers == other.supportedCiphers &&
          supportedHashes == other.supportedHashes &&
          supportedAsymSpec == other.supportedAsymSpec;
}

/// Enum describing the security level of a provider.
///
/// * [SecurityLevel::Hardware]: Provider is hardware backed (tpm, other security chips, StrongBox KeyStore).
/// * [SecurityLevel::Software]: Provder uses the systems software keystore.
/// * [SecurityLevel::Network]: Provider uses a network key store (Hashicorp).
/// * [SecurityLevel::Unsafe]: Provder uses software fallback.
enum SecurityLevel {
  /// Highest security level
  hardware,
  software,
  network,
  unsafe,
  ;
}

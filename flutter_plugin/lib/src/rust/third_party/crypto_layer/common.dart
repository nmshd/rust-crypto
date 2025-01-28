// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.7.1.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../frb_generated.dart';
import 'common/config.dart';
import 'common/crypto/algorithms/encryption.dart';
import 'common/crypto/algorithms/hashes.dart';
import 'common/error.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `clone`, `clone`, `fmt`, `fmt`, `fmt`

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<DHExchange>>
abstract class DhExchange implements RustOpaqueInterface {
  Future<Uint8List> addExternal({required List<int> externalKey});

  Future<KeyHandle> addExternalFinal({required List<int> externalKey});

  Future<Uint8List> getPublicKey();
}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<KeyHandle>>
abstract class KeyHandle implements RustOpaqueInterface {
  Future<Uint8List> decryptData(
      {required List<int> encryptedData, required List<int> iv});

  Future<void> delete();

  Future<(Uint8List, Uint8List)> encryptData({required List<int> data});

  Future<Uint8List> extractKey();

  Future<Uint8List> hmac({required List<int> data});

  Future<String> id();

  Future<KeySpec> spec();

  Future<bool> verifyHmac({required List<int> data, required List<int> hmac});
}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<KeyPairHandle>>
abstract class KeyPairHandle implements RustOpaqueInterface {
  /// Abstraction of asymmetric key pair handles.
  Future<Uint8List> decryptData({required List<int> data});

  /// Abstraction of asymmetric key pair handles.
  Future<void> delete();

  /// Abstraction of asymmetric key pair handles.
  Future<Uint8List> encryptData({required List<int> data});

  /// Abstraction of asymmetric key pair handles.
  Future<Uint8List> extractKey();

  /// Abstraction of asymmetric key pair handles.
  Future<Uint8List> getPublicKey();

  /// Abstraction of asymmetric key pair handles.
  Future<String> id();

  /// Abstraction of asymmetric key pair handles.
  Future<Uint8List> signData({required List<int> data});

  /// Abstraction of asymmetric key pair handles.
  Future<KeyPairSpec> spec();

  /// Abstraction of asymmetric key pair handles.
  Future<bool> verifySignature(
      {required List<int> data, required List<int> signature});
}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<Provider>>
abstract class Provider implements RustOpaqueInterface {
  Future<KeyHandle> createKey({required KeySpec spec});

  Future<KeyPairHandle> createKeyPair({required KeyPairSpec spec});

  Future<List<(String, Spec)>> getAllKeys();

  Future<ProviderConfig?> getCapabilities();

  Future<KeyHandle> importKey({required KeySpec spec, required List<int> data});

  Future<KeyPairHandle> importKeyPair(
      {required KeyPairSpec spec,
      required List<int> publicKey,
      required List<int> privateKey});

  Future<KeyPairHandle> importPublicKey(
      {required KeyPairSpec spec, required List<int> publicKey});

  Future<KeyHandle> loadKey({required String id});

  Future<KeyPairHandle> loadKeyPair({required String id});

  Future<String> providerName();

  Future<DhExchange> startEphemeralDhExchange({required KeyPairSpec spec});
}

/// ¯\_(ツ)_/¯
class T {
  const T();

  @override
  int get hashCode => 0;

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is T && runtimeType == other.runtimeType;
}

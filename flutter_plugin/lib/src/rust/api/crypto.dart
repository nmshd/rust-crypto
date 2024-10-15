// This file is automatically generated, so please do not edit it.
// Generated by `flutter_rust_bridge`@ 2.3.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

// These functions are ignored because they are not marked as `pub`: `get_java_vm`

Future<Provider> getProvider() =>
    RustLib.instance.api.crateApiCryptoGetProvider();

Future<KeyPairHandle> createKeyPair({required Provider provider}) =>
    RustLib.instance.api.crateApiCryptoCreateKeyPair(provider: provider);

Future<Uint8List> sign(
        {required KeyPairHandle keyPairHandle, required List<int> data}) =>
    RustLib.instance.api
        .crateApiCryptoSign(keyPairHandle: keyPairHandle, data: data);

Future<bool> verify(
        {required KeyPairHandle keyPairHandle,
        required List<int> data,
        required List<int> signature}) =>
    RustLib.instance.api.crateApiCryptoVerify(
        keyPairHandle: keyPairHandle, data: data, signature: signature);

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<KeyPairHandle>>
abstract class KeyPairHandle implements RustOpaqueInterface {}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<Provider>>
abstract class Provider implements RustOpaqueInterface {}

// Rust type: RustOpaqueMoi<flutter_rust_bridge::for_generated::RustAutoOpaqueInner< SecurityModuleError>>
abstract class SecurityModuleError implements RustOpaqueInterface {}

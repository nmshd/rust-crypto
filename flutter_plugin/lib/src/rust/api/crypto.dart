// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.6.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../frb_generated.dart';
import '../third_party/crypto_layer/common/config.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

Future<ProviderImplConfig> getDefaultConfig(
        {required FutureOr<Uint8List?> Function(String) getFn,
        required FutureOr<bool> Function(String, Uint8List) storeFn,
        required FutureOr<void> Function(String) deleteFn,
        required FutureOr<List<String>> Function() allKeysFn}) =>
    RustLib.instance.api.crateApiCryptoGetDefaultConfig(
        getFn: getFn,
        storeFn: storeFn,
        deleteFn: deleteFn,
        allKeysFn: allKeysFn);

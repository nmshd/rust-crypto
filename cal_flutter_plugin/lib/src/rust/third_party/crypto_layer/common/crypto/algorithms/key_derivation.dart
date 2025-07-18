// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.9.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../../../../frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:freezed_annotation/freezed_annotation.dart' hide protected;
part 'key_derivation.freezed.dart';

// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `clone`, `clone`, `fmt`, `fmt`

/// flutter_rust_bridge:non_opaque
class Argon2Options {
  /// Memory cost in kibibytes
  final int memory;

  /// Number of iterations
  final int iterations;

  /// Degree of parallelism
  final int parallelism;

  const Argon2Options({
    required this.memory,
    required this.iterations,
    required this.parallelism,
  });

  static Future<Argon2Options> default_() => RustLib.instance.api
      .cryptoLayerCommonCryptoAlgorithmsKeyDerivationArgon2OptionsDefault();

  @override
  int get hashCode =>
      memory.hashCode ^ iterations.hashCode ^ parallelism.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Argon2Options &&
          runtimeType == other.runtimeType &&
          memory == other.memory &&
          iterations == other.iterations &&
          parallelism == other.parallelism;
}

@freezed
sealed class KDF with _$KDF {
  const KDF._();

  /// Strong brute force resistance, no side channel resistance.
  const factory KDF.argon2D(Argon2Options field0) = KDF_Argon2d;

  /// Partial brute force and partial side channel resistance.
  const factory KDF.argon2Id(Argon2Options field0) = KDF_Argon2id;
  const factory KDF.argon2I(Argon2Options field0) = KDF_Argon2i;

  static Future<KDF> default_() => RustLib.instance.api
      .cryptoLayerCommonCryptoAlgorithmsKeyDerivationKdfDefault();
}

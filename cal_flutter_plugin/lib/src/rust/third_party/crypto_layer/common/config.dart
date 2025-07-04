// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.9.0.

// ignore_for_file: invalid_use_of_internal_member, unused_import, unnecessary_import

import '../../../frb_generated.dart';
import '../../../lib.dart';
import '../common.dart';
import 'crypto/algorithms/encryption.dart';
import 'crypto/algorithms/hashes.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:freezed_annotation/freezed_annotation.dart' hide protected;
part 'config.freezed.dart';

// These types are ignored because they are neither used by any `pub` functions nor (for structs and enums) marked `#[frb(unignore)]`: `AdditionalConfigDiscriminants`, `SecurityLevelIter`
// These function are ignored because they are on traits that is not defined in current crate (put an empty `#[frb]` on it to unignore): `assert_receiver_is_total_eq`, `assert_receiver_is_total_eq`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `clone`, `cmp`, `eq`, `eq`, `eq`, `eq`, `eq`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `fmt`, `from_str`, `from_str`, `from`, `from`, `from`, `from`, `from`, `from`, `iter`, `len`, `next_back`, `next`, `nth`, `partial_cmp`, `size_hint`, `try_from`, `try_from`, `zeroize`

@freezed
sealed class AdditionalConfig with _$AdditionalConfig {
  const AdditionalConfig._();

  /// Callback functions acting like a hashmap for storing key metadata.
  ///
  /// Mutually exclusive with [AdditionalConfig::FileStoreConfig].
  const factory AdditionalConfig.kvStoreConfig({
    required ArcFnStringDynFutureOptionVecU8 getFn,
    required ArcFnStringVecU8DynFutureBool storeFn,
    required ArcFnStringPinBoxFutureOutput deleteFn,
    required ArcFnDynFutureVecString allKeysFn,
  }) = AdditionalConfig_KVStoreConfig;

  /// Configuration for the usage of the metadata file database.
  ///
  /// Mutually exclusive with [AdditionalConfig::KVStoreConfig].
  const factory AdditionalConfig.fileStoreConfig({
    /// Path to a directory where the database holding key metadata will be saved.
    required String dbDir,
  }) = AdditionalConfig_FileStoreConfig;

  /// Enables integrity verification of key metadata.
  ///
  /// Mutually exclusive with [AdditionalConfig::StorageConfigDSA].
  const factory AdditionalConfig.storageConfigHmac(KeyHandle field0) =
      AdditionalConfig_StorageConfigHMAC;

  /// Enables integrity verification of key metadata.
  ///
  /// Mutually exclusive with [AdditionalConfig::StorageConfigHMAC].
  const factory AdditionalConfig.storageConfigDsa(KeyPairHandle field0) =
      AdditionalConfig_StorageConfigDSA;

  /// Enables encryption of sensitive key metadata.
  ///
  /// In case of the software provider, this enables encryption of secret keys.
  ///
  /// Mutually exclusive with [AdditionalConfig::StorageConfigAsymmetricEncryption].
  const factory AdditionalConfig.storageConfigSymmetricEncryption(
    KeyHandle field0,
  ) = AdditionalConfig_StorageConfigSymmetricEncryption;

  /// Enables encryption of sensitive key metadata.
  ///
  /// In case of the software provider, this enables encryption of secret keys.
  ///
  /// Mutually exclusive with [AdditionalConfig::StorageConfigSymmetricEncryption].
  const factory AdditionalConfig.storageConfigAsymmetricEncryption(
    KeyPairHandle field0,
  ) = AdditionalConfig_StorageConfigAsymmetricEncryption;
}

/// Struct used to configure key pairs.
/// flutter_rust_bridge:non_opaque
class KeyPairSpec {
  /// Asymmetric algorithm to be used.
  final AsymmetricKeySpec asymSpec;

  /// Cipher used for hybrid encryption. If set to None, no hybrid encryption will be used.
  final Cipher? cipher;

  /// Hash function used for signing and encrypting.
  final CryptoHash signingHash;

  /// If set to true, the key pair will be discarded after the handle is dropped.
  final bool ephemeral;

  /// If set to true, the key can't be exported (also software keys)
  final bool nonExportable;

  const KeyPairSpec({
    required this.asymSpec,
    this.cipher,
    required this.signingHash,
    required this.ephemeral,
    required this.nonExportable,
  });

  static Future<KeyPairSpec> default_() =>
      RustLib.instance.api.cryptoLayerCommonConfigKeyPairSpecDefault();

  @override
  int get hashCode =>
      asymSpec.hashCode ^
      cipher.hashCode ^
      signingHash.hashCode ^
      ephemeral.hashCode ^
      nonExportable.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeyPairSpec &&
          runtimeType == other.runtimeType &&
          asymSpec == other.asymSpec &&
          cipher == other.cipher &&
          signingHash == other.signingHash &&
          ephemeral == other.ephemeral &&
          nonExportable == other.nonExportable;
}

/// Struct used to configure keys.
/// flutter_rust_bridge:non_opaque
class KeySpec {
  /// Cipher used for symmetric encryption.
  final Cipher cipher;

  /// Hash function used with HMAC.
  final CryptoHash signingHash;

  /// If set to `true`, the key is going to be deleted when the handle is dropped.
  final bool ephemeral;

  /// If set to `true`, the key cannot be exported.
  final bool nonExportable;

  const KeySpec({
    required this.cipher,
    required this.signingHash,
    required this.ephemeral,
    required this.nonExportable,
  });

  static Future<KeySpec> default_() =>
      RustLib.instance.api.cryptoLayerCommonConfigKeySpecDefault();

  @override
  int get hashCode =>
      cipher.hashCode ^
      signingHash.hashCode ^
      ephemeral.hashCode ^
      nonExportable.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeySpec &&
          runtimeType == other.runtimeType &&
          cipher == other.cipher &&
          signingHash == other.signingHash &&
          ephemeral == other.ephemeral &&
          nonExportable == other.nonExportable;
}

/// Capabilities of a Provider
/// flutter_rust_bridge:non_opaque
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

/// Configuration needed for using or initializing providers.
///
/// Either
/// * [AdditionalConfig::KVStoreConfig]
/// * [AdditionalConfig::FileStoreConfig]
///
/// and either
/// * [AdditionalConfig::StorageConfigHMAC]
/// * [AdditionalConfig::StorageConfigDSA]
/// * [AdditionalConfig::StorageConfigPass]
///
/// need to be supplied.
///
/// ## Example
///
/// ```rust
/// use crypto_layer::prelude::*;
/// let implementation_config = ProviderImplConfig {
///       additional_config: vec![
///          AdditionalConfig::FileStoreConfig {
///              db_dir: "./testdb".to_owned(),
///          }
///      ],
/// };
/// ```
/// flutter_rust_bridge:non_opaque
class ProviderImplConfig {
  final List<AdditionalConfig> additionalConfig;

  const ProviderImplConfig({required this.additionalConfig});

  // HINT: Make it `#[frb(sync)]` to let it become the default constructor of Dart class.
  /// Creates a new `ProviderImplConfig` instance.
  static Future<ProviderImplConfig> newInstance({
    required ArcFnStringDynFutureOptionVecU8 getFn,
    required ArcFnStringVecU8DynFutureBool storeFn,
    required ArcFnStringPinBoxFutureOutput deleteFn,
    required ArcFnDynFutureVecString allKeysFn,
    required List<AdditionalConfig> additionalConfig,
  }) => RustLib.instance.api.cryptoLayerCommonConfigProviderImplConfigNew(
    getFn: getFn,
    storeFn: storeFn,
    deleteFn: deleteFn,
    allKeysFn: allKeysFn,
    additionalConfig: additionalConfig,
  );

  @override
  int get hashCode => additionalConfig.hashCode;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ProviderImplConfig &&
          runtimeType == other.runtimeType &&
          additionalConfig == other.additionalConfig;
}

/// Enum describing the security level of a provider.
///
/// * [SecurityLevel::Hardware]: Provider is hardware backed (tpm, other security chips, StrongBox KeyStore).
/// * [SecurityLevel::Software]: Provider uses the systems software keystore.
/// * [SecurityLevel::Network]: Provider uses a network key store (Hashicorp).
/// * [SecurityLevel::Unsafe]: Provider uses software fallback.
enum SecurityLevel {
  /// Highest security level.
  ///
  /// Implies running on a TPM, HSM or TEE.
  /// The extraction of private keys is impossible.
  hardware,

  /// Keys are stored in an encrypted database or on a native software key store.
  ///
  /// Extraction of private keys is possible.
  software,

  /// NKS
  ///
  /// Extraction of private keys is possible.
  network,

  /// Lowest security level.
  ///
  /// Keys are stored in an unencrypted, insecure database or file.
  unsafe,
}

@freezed
sealed class Spec with _$Spec {
  const Spec._();

  const factory Spec.keySpec(KeySpec field0) = Spec_KeySpec;
  const factory Spec.keyPairSpec(KeyPairSpec field0) = Spec_KeyPairSpec;
}

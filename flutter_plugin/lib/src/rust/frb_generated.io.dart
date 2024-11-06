// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.5.1.

// ignore_for_file: unused_import, unused_element, unnecessary_import, duplicate_ignore, invalid_use_of_internal_member, annotate_overrides, non_constant_identifier_names, curly_braces_in_flow_control_structures, prefer_const_literals_to_create_immutables, unused_field

import 'api/crypto.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated_io.dart';
import 'third_party/crypto_layer/common.dart';
import 'third_party/crypto_layer/common/config.dart';
import 'third_party/crypto_layer/common/crypto/algorithms.dart';
import 'third_party/crypto_layer/common/crypto/algorithms/encryption.dart';
import 'third_party/crypto_layer/common/crypto/algorithms/hashes.dart';
import 'third_party/crypto_layer/common/crypto/pkcs/standards.dart';
import 'third_party/crypto_layer/common/error.dart';
import 'third_party/crypto_layer/common/factory.dart';

abstract class RustLibApiImplPlatform extends BaseApiImpl<RustLibWire> {
  RustLibApiImplPlatform({
    required super.handler,
    required super.wire,
    required super.generalizedFrbRustBinding,
    required super.portManager,
  });

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_CalErrorPtr => wire
      ._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalErrorPtr;

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_DhExchangePtr =>
      wire._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchangePtr;

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_KeyHandlePtr =>
      wire._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandlePtr;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_KeyPairHandlePtr => wire
          ._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandlePtr;

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_ProviderPtr => wire
      ._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderPtr;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_ProviderImplConfigPtr => wire
          ._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfigPtr;

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_TPtr => wire
      ._rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerTPtr;

  @protected
  AnyhowException dco_decode_AnyhowException(dynamic raw);

  @protected
  CalError
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          dynamic raw);

  @protected
  DhExchange
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
          dynamic raw);

  @protected
  KeyHandle
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          dynamic raw);

  @protected
  KeyPairHandle
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          dynamic raw);

  @protected
  Provider
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw);

  @protected
  ProviderImplConfig
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
          dynamic raw);

  @protected
  T dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
      dynamic raw);

  @protected
  Provider
      dco_decode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw);

  @protected
  CalError
      dco_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          dynamic raw);

  @protected
  KeyHandle
      dco_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          dynamic raw);

  @protected
  KeyPairHandle
      dco_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          dynamic raw);

  @protected
  Provider
      dco_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw);

  @protected
  FutureOr<Uint8List?> Function(String)
      dco_decode_DartFn_Inputs_String_Output_opt_list_prim_u_8_strict_AnyhowException(
          dynamic raw);

  @protected
  FutureOr<bool> Function(String, Uint8List)
      dco_decode_DartFn_Inputs_String_list_prim_u_8_strict_Output_bool_AnyhowException(
          dynamic raw);

  @protected
  FutureOr<List<String>> Function()
      dco_decode_DartFn_Inputs__Output_list_String_AnyhowException(dynamic raw);

  @protected
  Object dco_decode_DartOpaque(dynamic raw);

  @protected
  CalError
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          dynamic raw);

  @protected
  DhExchange
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
          dynamic raw);

  @protected
  KeyHandle
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          dynamic raw);

  @protected
  KeyPairHandle
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          dynamic raw);

  @protected
  Provider
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw);

  @protected
  ProviderImplConfig
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
          dynamic raw);

  @protected
  T dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
      dynamic raw);

  @protected
  Set<AsymmetricKeySpec> dco_decode_Set_asymmetric_key_spec(dynamic raw);

  @protected
  Set<Cipher> dco_decode_Set_cipher(dynamic raw);

  @protected
  Set<CryptoHash> dco_decode_Set_crypto_hash(dynamic raw);

  @protected
  String dco_decode_String(dynamic raw);

  @protected
  ToCalError dco_decode_TraitDef_ToCalError(dynamic raw);

  @protected
  AsymmetricKeySpec dco_decode_asymmetric_key_spec(dynamic raw);

  @protected
  bool dco_decode_bool(dynamic raw);

  @protected
  Provider
      dco_decode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw);

  @protected
  Cipher dco_decode_box_autoadd_cipher(dynamic raw);

  @protected
  KeyPairSpec dco_decode_box_autoadd_key_pair_spec(dynamic raw);

  @protected
  KeySpec dco_decode_box_autoadd_key_spec(dynamic raw);

  @protected
  ProviderConfig dco_decode_box_autoadd_provider_config(dynamic raw);

  @protected
  CalErrorKind dco_decode_cal_error_kind(dynamic raw);

  @protected
  ChCha20Mode dco_decode_ch_cha_20_mode(dynamic raw);

  @protected
  Cipher dco_decode_cipher(dynamic raw);

  @protected
  CryptoHash dco_decode_crypto_hash(dynamic raw);

  @protected
  EccCurve dco_decode_ecc_curve(dynamic raw);

  @protected
  EccSigningScheme dco_decode_ecc_signing_scheme(dynamic raw);

  @protected
  int dco_decode_i_32(dynamic raw);

  @protected
  PlatformInt64 dco_decode_isize(dynamic raw);

  @protected
  KeyBits dco_decode_key_bits(dynamic raw);

  @protected
  KeyPairSpec dco_decode_key_pair_spec(dynamic raw);

  @protected
  KeySpec dco_decode_key_spec(dynamic raw);

  @protected
  KeyType dco_decode_key_type(dynamic raw);

  @protected
  List<String> dco_decode_list_String(dynamic raw);

  @protected
  List<AsymmetricKeySpec> dco_decode_list_asymmetric_key_spec(dynamic raw);

  @protected
  List<Cipher> dco_decode_list_cipher(dynamic raw);

  @protected
  List<CryptoHash> dco_decode_list_crypto_hash(dynamic raw);

  @protected
  List<int> dco_decode_list_prim_u_8_loose(dynamic raw);

  @protected
  Uint8List dco_decode_list_prim_u_8_strict(dynamic raw);

  @protected
  OidType dco_decode_oid_type(dynamic raw);

  @protected
  Provider?
      dco_decode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw);

  @protected
  Cipher? dco_decode_opt_box_autoadd_cipher(dynamic raw);

  @protected
  Uint8List? dco_decode_opt_list_prim_u_8_strict(dynamic raw);

  @protected
  ProviderConfig dco_decode_provider_config(dynamic raw);

  @protected
  Rc2KeyBits dco_decode_rc_2_key_bits(dynamic raw);

  @protected
  SecurityLevel dco_decode_security_level(dynamic raw);

  @protected
  Sha2Bits dco_decode_sha_2_bits(dynamic raw);

  @protected
  Sha3Bits dco_decode_sha_3_bits(dynamic raw);

  @protected
  SymmetricMode dco_decode_symmetric_mode(dynamic raw);

  @protected
  TripleDesNumKeys dco_decode_triple_des_num_keys(dynamic raw);

  @protected
  int dco_decode_u_8(dynamic raw);

  @protected
  void dco_decode_unit(dynamic raw);

  @protected
  BigInt dco_decode_usize(dynamic raw);

  @protected
  AnyhowException sse_decode_AnyhowException(SseDeserializer deserializer);

  @protected
  CalError
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          SseDeserializer deserializer);

  @protected
  DhExchange
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
          SseDeserializer deserializer);

  @protected
  KeyHandle
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          SseDeserializer deserializer);

  @protected
  KeyPairHandle
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          SseDeserializer deserializer);

  @protected
  Provider
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer);

  @protected
  ProviderImplConfig
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
          SseDeserializer deserializer);

  @protected
  T sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
      SseDeserializer deserializer);

  @protected
  Provider
      sse_decode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer);

  @protected
  CalError
      sse_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          SseDeserializer deserializer);

  @protected
  KeyHandle
      sse_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          SseDeserializer deserializer);

  @protected
  KeyPairHandle
      sse_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          SseDeserializer deserializer);

  @protected
  Provider
      sse_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer);

  @protected
  Object sse_decode_DartOpaque(SseDeserializer deserializer);

  @protected
  CalError
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          SseDeserializer deserializer);

  @protected
  DhExchange
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
          SseDeserializer deserializer);

  @protected
  KeyHandle
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          SseDeserializer deserializer);

  @protected
  KeyPairHandle
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          SseDeserializer deserializer);

  @protected
  Provider
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer);

  @protected
  ProviderImplConfig
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
          SseDeserializer deserializer);

  @protected
  T sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
      SseDeserializer deserializer);

  @protected
  Set<AsymmetricKeySpec> sse_decode_Set_asymmetric_key_spec(
      SseDeserializer deserializer);

  @protected
  Set<Cipher> sse_decode_Set_cipher(SseDeserializer deserializer);

  @protected
  Set<CryptoHash> sse_decode_Set_crypto_hash(SseDeserializer deserializer);

  @protected
  String sse_decode_String(SseDeserializer deserializer);

  @protected
  AsymmetricKeySpec sse_decode_asymmetric_key_spec(
      SseDeserializer deserializer);

  @protected
  bool sse_decode_bool(SseDeserializer deserializer);

  @protected
  Provider
      sse_decode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer);

  @protected
  Cipher sse_decode_box_autoadd_cipher(SseDeserializer deserializer);

  @protected
  KeyPairSpec sse_decode_box_autoadd_key_pair_spec(
      SseDeserializer deserializer);

  @protected
  KeySpec sse_decode_box_autoadd_key_spec(SseDeserializer deserializer);

  @protected
  ProviderConfig sse_decode_box_autoadd_provider_config(
      SseDeserializer deserializer);

  @protected
  CalErrorKind sse_decode_cal_error_kind(SseDeserializer deserializer);

  @protected
  ChCha20Mode sse_decode_ch_cha_20_mode(SseDeserializer deserializer);

  @protected
  Cipher sse_decode_cipher(SseDeserializer deserializer);

  @protected
  CryptoHash sse_decode_crypto_hash(SseDeserializer deserializer);

  @protected
  EccCurve sse_decode_ecc_curve(SseDeserializer deserializer);

  @protected
  EccSigningScheme sse_decode_ecc_signing_scheme(SseDeserializer deserializer);

  @protected
  int sse_decode_i_32(SseDeserializer deserializer);

  @protected
  PlatformInt64 sse_decode_isize(SseDeserializer deserializer);

  @protected
  KeyBits sse_decode_key_bits(SseDeserializer deserializer);

  @protected
  KeyPairSpec sse_decode_key_pair_spec(SseDeserializer deserializer);

  @protected
  KeySpec sse_decode_key_spec(SseDeserializer deserializer);

  @protected
  KeyType sse_decode_key_type(SseDeserializer deserializer);

  @protected
  List<String> sse_decode_list_String(SseDeserializer deserializer);

  @protected
  List<AsymmetricKeySpec> sse_decode_list_asymmetric_key_spec(
      SseDeserializer deserializer);

  @protected
  List<Cipher> sse_decode_list_cipher(SseDeserializer deserializer);

  @protected
  List<CryptoHash> sse_decode_list_crypto_hash(SseDeserializer deserializer);

  @protected
  List<int> sse_decode_list_prim_u_8_loose(SseDeserializer deserializer);

  @protected
  Uint8List sse_decode_list_prim_u_8_strict(SseDeserializer deserializer);

  @protected
  OidType sse_decode_oid_type(SseDeserializer deserializer);

  @protected
  Provider?
      sse_decode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer);

  @protected
  Cipher? sse_decode_opt_box_autoadd_cipher(SseDeserializer deserializer);

  @protected
  Uint8List? sse_decode_opt_list_prim_u_8_strict(SseDeserializer deserializer);

  @protected
  ProviderConfig sse_decode_provider_config(SseDeserializer deserializer);

  @protected
  Rc2KeyBits sse_decode_rc_2_key_bits(SseDeserializer deserializer);

  @protected
  SecurityLevel sse_decode_security_level(SseDeserializer deserializer);

  @protected
  Sha2Bits sse_decode_sha_2_bits(SseDeserializer deserializer);

  @protected
  Sha3Bits sse_decode_sha_3_bits(SseDeserializer deserializer);

  @protected
  SymmetricMode sse_decode_symmetric_mode(SseDeserializer deserializer);

  @protected
  TripleDesNumKeys sse_decode_triple_des_num_keys(SseDeserializer deserializer);

  @protected
  int sse_decode_u_8(SseDeserializer deserializer);

  @protected
  void sse_decode_unit(SseDeserializer deserializer);

  @protected
  BigInt sse_decode_usize(SseDeserializer deserializer);

  @protected
  void sse_encode_AnyhowException(
      AnyhowException self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          CalError self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
          DhExchange self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          KeyHandle self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          KeyPairHandle self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
          ProviderImplConfig self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
          T self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          CalError self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          KeyHandle self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          KeyPairHandle self, SseSerializer serializer);

  @protected
  void
      sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer);

  @protected
  void
      sse_encode_DartFn_Inputs_String_Output_opt_list_prim_u_8_strict_AnyhowException(
          FutureOr<Uint8List?> Function(String) self, SseSerializer serializer);

  @protected
  void
      sse_encode_DartFn_Inputs_String_list_prim_u_8_strict_Output_bool_AnyhowException(
          FutureOr<bool> Function(String, Uint8List) self,
          SseSerializer serializer);

  @protected
  void sse_encode_DartFn_Inputs__Output_list_String_AnyhowException(
      FutureOr<List<String>> Function() self, SseSerializer serializer);

  @protected
  void sse_encode_DartOpaque(Object self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
          CalError self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
          DhExchange self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
          KeyHandle self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          KeyPairHandle self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
          ProviderImplConfig self, SseSerializer serializer);

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
          T self, SseSerializer serializer);

  @protected
  void sse_encode_Set_asymmetric_key_spec(
      Set<AsymmetricKeySpec> self, SseSerializer serializer);

  @protected
  void sse_encode_Set_cipher(Set<Cipher> self, SseSerializer serializer);

  @protected
  void sse_encode_Set_crypto_hash(
      Set<CryptoHash> self, SseSerializer serializer);

  @protected
  void sse_encode_String(String self, SseSerializer serializer);

  @protected
  void sse_encode_asymmetric_key_spec(
      AsymmetricKeySpec self, SseSerializer serializer);

  @protected
  void sse_encode_bool(bool self, SseSerializer serializer);

  @protected
  void
      sse_encode_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_cipher(Cipher self, SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_key_pair_spec(
      KeyPairSpec self, SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_key_spec(KeySpec self, SseSerializer serializer);

  @protected
  void sse_encode_box_autoadd_provider_config(
      ProviderConfig self, SseSerializer serializer);

  @protected
  void sse_encode_cal_error_kind(CalErrorKind self, SseSerializer serializer);

  @protected
  void sse_encode_ch_cha_20_mode(ChCha20Mode self, SseSerializer serializer);

  @protected
  void sse_encode_cipher(Cipher self, SseSerializer serializer);

  @protected
  void sse_encode_crypto_hash(CryptoHash self, SseSerializer serializer);

  @protected
  void sse_encode_ecc_curve(EccCurve self, SseSerializer serializer);

  @protected
  void sse_encode_ecc_signing_scheme(
      EccSigningScheme self, SseSerializer serializer);

  @protected
  void sse_encode_i_32(int self, SseSerializer serializer);

  @protected
  void sse_encode_isize(PlatformInt64 self, SseSerializer serializer);

  @protected
  void sse_encode_key_bits(KeyBits self, SseSerializer serializer);

  @protected
  void sse_encode_key_pair_spec(KeyPairSpec self, SseSerializer serializer);

  @protected
  void sse_encode_key_spec(KeySpec self, SseSerializer serializer);

  @protected
  void sse_encode_key_type(KeyType self, SseSerializer serializer);

  @protected
  void sse_encode_list_String(List<String> self, SseSerializer serializer);

  @protected
  void sse_encode_list_asymmetric_key_spec(
      List<AsymmetricKeySpec> self, SseSerializer serializer);

  @protected
  void sse_encode_list_cipher(List<Cipher> self, SseSerializer serializer);

  @protected
  void sse_encode_list_crypto_hash(
      List<CryptoHash> self, SseSerializer serializer);

  @protected
  void sse_encode_list_prim_u_8_loose(List<int> self, SseSerializer serializer);

  @protected
  void sse_encode_list_prim_u_8_strict(
      Uint8List self, SseSerializer serializer);

  @protected
  void sse_encode_oid_type(OidType self, SseSerializer serializer);

  @protected
  void
      sse_encode_opt_box_autoadd_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider? self, SseSerializer serializer);

  @protected
  void sse_encode_opt_box_autoadd_cipher(
      Cipher? self, SseSerializer serializer);

  @protected
  void sse_encode_opt_list_prim_u_8_strict(
      Uint8List? self, SseSerializer serializer);

  @protected
  void sse_encode_provider_config(
      ProviderConfig self, SseSerializer serializer);

  @protected
  void sse_encode_rc_2_key_bits(Rc2KeyBits self, SseSerializer serializer);

  @protected
  void sse_encode_security_level(SecurityLevel self, SseSerializer serializer);

  @protected
  void sse_encode_sha_2_bits(Sha2Bits self, SseSerializer serializer);

  @protected
  void sse_encode_sha_3_bits(Sha3Bits self, SseSerializer serializer);

  @protected
  void sse_encode_symmetric_mode(SymmetricMode self, SseSerializer serializer);

  @protected
  void sse_encode_triple_des_num_keys(
      TripleDesNumKeys self, SseSerializer serializer);

  @protected
  void sse_encode_u_8(int self, SseSerializer serializer);

  @protected
  void sse_encode_unit(void self, SseSerializer serializer);

  @protected
  void sse_encode_usize(BigInt self, SseSerializer serializer);
}

// Section: wire_class

class RustLibWire implements BaseWire {
  factory RustLibWire.fromExternalLibrary(ExternalLibrary lib) =>
      RustLibWire(lib.ffiDynamicLibrary);

  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  RustLibWire(ffi.DynamicLibrary dynamicLibrary)
      : _lookup = dynamicLibrary.lookup;

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalErrorPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalErrorPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalErrorPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalError =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerCalErrorPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchangePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchangePtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchangePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchange =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerDHExchangePtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandlePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandlePtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandlePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandle =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyHandlePtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandlePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandlePtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandlePtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandlePtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfigPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfigPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfigPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfig =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProviderImplConfigPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
      ptr,
    );
  }

  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerTPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT');
  late final _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT =
      _rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerTPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();

  void
      rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
    ffi.Pointer<ffi.Void> ptr,
  ) {
    return _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT(
      ptr,
    );
  }

  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerTPtr =
      _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>(
          'frbgen_cal_flutter_plugin_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT');
  late final _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerT =
      _rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerTPtr
          .asFunction<void Function(ffi.Pointer<ffi.Void>)>();
}

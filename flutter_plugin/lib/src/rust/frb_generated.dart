// This file is automatically generated, so please do not edit it.
// @generated by `flutter_rust_bridge`@ 2.4.0.

// ignore_for_file: unused_import, unused_element, unnecessary_import, duplicate_ignore, invalid_use_of_internal_member, annotate_overrides, non_constant_identifier_names, curly_braces_in_flow_control_structures, prefer_const_literals_to_create_immutables, unused_field

import 'api/crypto.dart';
import 'api/simple.dart';
import 'dart:async';
import 'dart:convert';
import 'frb_generated.dart';
import 'frb_generated.io.dart'
    if (dart.library.js_interop) 'frb_generated.web.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

/// Main entrypoint of the Rust API
class RustLib extends BaseEntrypoint<RustLibApi, RustLibApiImpl, RustLibWire> {
  @internal
  static final instance = RustLib._();

  RustLib._();

  /// Initialize flutter_rust_bridge
  static Future<void> init({
    RustLibApi? api,
    BaseHandler? handler,
    ExternalLibrary? externalLibrary,
  }) async {
    await instance.initImpl(
      api: api,
      handler: handler,
      externalLibrary: externalLibrary,
    );
  }

  /// Initialize flutter_rust_bridge in mock mode.
  /// No libraries for FFI are loaded.
  static void initMock({
    required RustLibApi api,
  }) {
    instance.initMockImpl(
      api: api,
    );
  }

  /// Dispose flutter_rust_bridge
  ///
  /// The call to this function is optional, since flutter_rust_bridge (and everything else)
  /// is automatically disposed when the app stops.
  static void dispose() => instance.disposeImpl();

  @override
  ApiImplConstructor<RustLibApiImpl, RustLibWire> get apiImplConstructor =>
      RustLibApiImpl.new;

  @override
  WireConstructor<RustLibWire> get wireConstructor =>
      RustLibWire.fromExternalLibrary;

  @override
  Future<void> executeRustInitializers() async {
    await api.crateApiSimpleInitApp();
  }

  @override
  ExternalLibraryLoaderConfig get defaultExternalLibraryLoaderConfig =>
      kDefaultExternalLibraryLoaderConfig;

  @override
  String get codegenVersion => '2.4.0';

  @override
  int get rustContentHash => -822278434;

  static const kDefaultExternalLibraryLoaderConfig =
      ExternalLibraryLoaderConfig(
    stem: 'cal_flutter_plugin',
    ioDirectory: 'rust/target/release/',
    webPrefix: 'pkg/',
  );
}

abstract class RustLibApi extends BaseApi {
  Future<KeyPairHandle> crateApiCryptoCreateKeyPair(
      {required Provider provider});

  Future<Provider> crateApiCryptoGetProvider();

  Future<Uint8List> crateApiCryptoSign(
      {required KeyPairHandle keyPairHandle, required List<int> data});

  Future<bool> crateApiCryptoVerify(
      {required KeyPairHandle keyPairHandle,
      required List<int> data,
      required List<int> signature});

  String crateApiSimpleGreet({required String name});

  Future<void> crateApiSimpleInitApp();

  RustArcIncrementStrongCountFnType
      get rust_arc_increment_strong_count_KeyPairHandle;

  RustArcDecrementStrongCountFnType
      get rust_arc_decrement_strong_count_KeyPairHandle;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_KeyPairHandlePtr;

  RustArcIncrementStrongCountFnType
      get rust_arc_increment_strong_count_Provider;

  RustArcDecrementStrongCountFnType
      get rust_arc_decrement_strong_count_Provider;

  CrossPlatformFinalizerArg get rust_arc_decrement_strong_count_ProviderPtr;

  RustArcIncrementStrongCountFnType
      get rust_arc_increment_strong_count_SecurityModuleError;

  RustArcDecrementStrongCountFnType
      get rust_arc_decrement_strong_count_SecurityModuleError;

  CrossPlatformFinalizerArg
      get rust_arc_decrement_strong_count_SecurityModuleErrorPtr;
}

class RustLibApiImpl extends RustLibApiImplPlatform implements RustLibApi {
  RustLibApiImpl({
    required super.handler,
    required super.wire,
    required super.generalizedFrbRustBinding,
    required super.portManager,
  });

  @override
  Future<KeyPairHandle> crateApiCryptoCreateKeyPair(
      {required Provider provider}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
            provider, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 1, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData:
            sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle,
        decodeErrorData:
            sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError,
      ),
      constMeta: kCrateApiCryptoCreateKeyPairConstMeta,
      argValues: [provider],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiCryptoCreateKeyPairConstMeta =>
      const TaskConstMeta(
        debugName: "create_key_pair",
        argNames: ["provider"],
      );

  @override
  Future<Provider> crateApiCryptoGetProvider() {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 2, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData:
            sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiCryptoGetProviderConstMeta,
      argValues: [],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiCryptoGetProviderConstMeta => const TaskConstMeta(
        debugName: "get_provider",
        argNames: [],
      );

  @override
  Future<Uint8List> crateApiCryptoSign(
      {required KeyPairHandle keyPairHandle, required List<int> data}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
            keyPairHandle, serializer);
        sse_encode_list_prim_u_8_loose(data, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 3, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_list_prim_u_8_strict,
        decodeErrorData:
            sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError,
      ),
      constMeta: kCrateApiCryptoSignConstMeta,
      argValues: [keyPairHandle, data],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiCryptoSignConstMeta => const TaskConstMeta(
        debugName: "sign",
        argNames: ["keyPairHandle", "data"],
      );

  @override
  Future<bool> crateApiCryptoVerify(
      {required KeyPairHandle keyPairHandle,
      required List<int> data,
      required List<int> signature}) {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
            keyPairHandle, serializer);
        sse_encode_list_prim_u_8_loose(data, serializer);
        sse_encode_list_prim_u_8_loose(signature, serializer);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 4, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_bool,
        decodeErrorData:
            sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError,
      ),
      constMeta: kCrateApiCryptoVerifyConstMeta,
      argValues: [keyPairHandle, data, signature],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiCryptoVerifyConstMeta => const TaskConstMeta(
        debugName: "verify",
        argNames: ["keyPairHandle", "data", "signature"],
      );

  @override
  String crateApiSimpleGreet({required String name}) {
    return handler.executeSync(SyncTask(
      callFfi: () {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        sse_encode_String(name, serializer);
        return pdeCallFfi(generalizedFrbRustBinding, serializer, funcId: 5)!;
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_String,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiSimpleGreetConstMeta,
      argValues: [name],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiSimpleGreetConstMeta => const TaskConstMeta(
        debugName: "greet",
        argNames: ["name"],
      );

  @override
  Future<void> crateApiSimpleInitApp() {
    return handler.executeNormal(NormalTask(
      callFfi: (port_) {
        final serializer = SseSerializer(generalizedFrbRustBinding);
        pdeCallFfi(generalizedFrbRustBinding, serializer,
            funcId: 6, port: port_);
      },
      codec: SseCodec(
        decodeSuccessData: sse_decode_unit,
        decodeErrorData: null,
      ),
      constMeta: kCrateApiSimpleInitAppConstMeta,
      argValues: [],
      apiImpl: this,
    ));
  }

  TaskConstMeta get kCrateApiSimpleInitAppConstMeta => const TaskConstMeta(
        debugName: "init_app",
        argNames: [],
      );

  RustArcIncrementStrongCountFnType
      get rust_arc_increment_strong_count_KeyPairHandle => wire
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle;

  RustArcDecrementStrongCountFnType
      get rust_arc_decrement_strong_count_KeyPairHandle => wire
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle;

  RustArcIncrementStrongCountFnType
      get rust_arc_increment_strong_count_Provider => wire
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider;

  RustArcDecrementStrongCountFnType
      get rust_arc_decrement_strong_count_Provider => wire
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider;

  RustArcIncrementStrongCountFnType
      get rust_arc_increment_strong_count_SecurityModuleError => wire
          .rust_arc_increment_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError;

  RustArcDecrementStrongCountFnType
      get rust_arc_decrement_strong_count_SecurityModuleError => wire
          .rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError;

  @protected
  KeyPairHandle
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return KeyPairHandleImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  Provider
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return ProviderImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  SecurityModuleError
      dco_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return SecurityModuleErrorImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  Provider
      dco_decode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return ProviderImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  KeyPairHandle
      dco_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return KeyPairHandleImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  KeyPairHandle
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return KeyPairHandleImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  Provider
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return ProviderImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  SecurityModuleError
      dco_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError(
          dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return SecurityModuleErrorImpl.frbInternalDcoDecode(raw as List<dynamic>);
  }

  @protected
  String dco_decode_String(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as String;
  }

  @protected
  bool dco_decode_bool(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as bool;
  }

  @protected
  List<int> dco_decode_list_prim_u_8_loose(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as List<int>;
  }

  @protected
  Uint8List dco_decode_list_prim_u_8_strict(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as Uint8List;
  }

  @protected
  int dco_decode_u_8(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return raw as int;
  }

  @protected
  void dco_decode_unit(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return;
  }

  @protected
  BigInt dco_decode_usize(dynamic raw) {
    // Codec=Dco (DartCObject based), see doc to use other codecs
    return dcoDecodeU64(raw);
  }

  @protected
  KeyPairHandle
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return KeyPairHandleImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  Provider
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return ProviderImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  SecurityModuleError
      sse_decode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return SecurityModuleErrorImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  Provider
      sse_decode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return ProviderImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  KeyPairHandle
      sse_decode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return KeyPairHandleImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  KeyPairHandle
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return KeyPairHandleImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  Provider
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return ProviderImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  SecurityModuleError
      sse_decode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError(
          SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return SecurityModuleErrorImpl.frbInternalSseDecode(
        sse_decode_usize(deserializer), sse_decode_i_32(deserializer));
  }

  @protected
  String sse_decode_String(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var inner = sse_decode_list_prim_u_8_strict(deserializer);
    return utf8.decoder.convert(inner);
  }

  @protected
  bool sse_decode_bool(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getUint8() != 0;
  }

  @protected
  List<int> sse_decode_list_prim_u_8_loose(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var len_ = sse_decode_i_32(deserializer);
    return deserializer.buffer.getUint8List(len_);
  }

  @protected
  Uint8List sse_decode_list_prim_u_8_strict(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    var len_ = sse_decode_i_32(deserializer);
    return deserializer.buffer.getUint8List(len_);
  }

  @protected
  int sse_decode_u_8(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getUint8();
  }

  @protected
  void sse_decode_unit(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
  }

  @protected
  BigInt sse_decode_usize(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getBigUint64();
  }

  @protected
  int sse_decode_i_32(SseDeserializer deserializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    return deserializer.buffer.getInt32();
  }

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          KeyPairHandle self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as KeyPairHandleImpl).frbInternalSseEncode(move: true),
        serializer);
  }

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as ProviderImpl).frbInternalSseEncode(move: true), serializer);
  }

  @protected
  void
      sse_encode_Auto_Owned_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError(
          SecurityModuleError self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as SecurityModuleErrorImpl).frbInternalSseEncode(move: true),
        serializer);
  }

  @protected
  void
      sse_encode_Auto_RefMut_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as ProviderImpl).frbInternalSseEncode(move: false), serializer);
  }

  @protected
  void
      sse_encode_Auto_Ref_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          KeyPairHandle self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as KeyPairHandleImpl).frbInternalSseEncode(move: false),
        serializer);
  }

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerKeyPairHandle(
          KeyPairHandle self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as KeyPairHandleImpl).frbInternalSseEncode(move: null),
        serializer);
  }

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerProvider(
          Provider self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as ProviderImpl).frbInternalSseEncode(move: null), serializer);
  }

  @protected
  void
      sse_encode_RustOpaque_flutter_rust_bridgefor_generatedRustAutoOpaqueInnerSecurityModuleError(
          SecurityModuleError self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_usize(
        (self as SecurityModuleErrorImpl).frbInternalSseEncode(move: null),
        serializer);
  }

  @protected
  void sse_encode_String(String self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_list_prim_u_8_strict(utf8.encoder.convert(self), serializer);
  }

  @protected
  void sse_encode_bool(bool self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putUint8(self ? 1 : 0);
  }

  @protected
  void sse_encode_list_prim_u_8_loose(
      List<int> self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_i_32(self.length, serializer);
    serializer.buffer
        .putUint8List(self is Uint8List ? self : Uint8List.fromList(self));
  }

  @protected
  void sse_encode_list_prim_u_8_strict(
      Uint8List self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    sse_encode_i_32(self.length, serializer);
    serializer.buffer.putUint8List(self);
  }

  @protected
  void sse_encode_u_8(int self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putUint8(self);
  }

  @protected
  void sse_encode_unit(void self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
  }

  @protected
  void sse_encode_usize(BigInt self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putBigUint64(self);
  }

  @protected
  void sse_encode_i_32(int self, SseSerializer serializer) {
    // Codec=Sse (Serialization based), see doc to use other codecs
    serializer.buffer.putInt32(self);
  }
}

@sealed
class KeyPairHandleImpl extends RustOpaque implements KeyPairHandle {
  // Not to be used by end users
  KeyPairHandleImpl.frbInternalDcoDecode(List<dynamic> wire)
      : super.frbInternalDcoDecode(wire, _kStaticData);

  // Not to be used by end users
  KeyPairHandleImpl.frbInternalSseDecode(BigInt ptr, int externalSizeOnNative)
      : super.frbInternalSseDecode(ptr, externalSizeOnNative, _kStaticData);

  static final _kStaticData = RustArcStaticData(
    rustArcIncrementStrongCount:
        RustLib.instance.api.rust_arc_increment_strong_count_KeyPairHandle,
    rustArcDecrementStrongCount:
        RustLib.instance.api.rust_arc_decrement_strong_count_KeyPairHandle,
    rustArcDecrementStrongCountPtr:
        RustLib.instance.api.rust_arc_decrement_strong_count_KeyPairHandlePtr,
  );
}

@sealed
class ProviderImpl extends RustOpaque implements Provider {
  // Not to be used by end users
  ProviderImpl.frbInternalDcoDecode(List<dynamic> wire)
      : super.frbInternalDcoDecode(wire, _kStaticData);

  // Not to be used by end users
  ProviderImpl.frbInternalSseDecode(BigInt ptr, int externalSizeOnNative)
      : super.frbInternalSseDecode(ptr, externalSizeOnNative, _kStaticData);

  static final _kStaticData = RustArcStaticData(
    rustArcIncrementStrongCount:
        RustLib.instance.api.rust_arc_increment_strong_count_Provider,
    rustArcDecrementStrongCount:
        RustLib.instance.api.rust_arc_decrement_strong_count_Provider,
    rustArcDecrementStrongCountPtr:
        RustLib.instance.api.rust_arc_decrement_strong_count_ProviderPtr,
  );
}

@sealed
class SecurityModuleErrorImpl extends RustOpaque
    implements SecurityModuleError {
  // Not to be used by end users
  SecurityModuleErrorImpl.frbInternalDcoDecode(List<dynamic> wire)
      : super.frbInternalDcoDecode(wire, _kStaticData);

  // Not to be used by end users
  SecurityModuleErrorImpl.frbInternalSseDecode(
      BigInt ptr, int externalSizeOnNative)
      : super.frbInternalSseDecode(ptr, externalSizeOnNative, _kStaticData);

  static final _kStaticData = RustArcStaticData(
    rustArcIncrementStrongCount: RustLib
        .instance.api.rust_arc_increment_strong_count_SecurityModuleError,
    rustArcDecrementStrongCount: RustLib
        .instance.api.rust_arc_decrement_strong_count_SecurityModuleError,
    rustArcDecrementStrongCountPtr: RustLib
        .instance.api.rust_arc_decrement_strong_count_SecurityModuleErrorPtr,
  );
}

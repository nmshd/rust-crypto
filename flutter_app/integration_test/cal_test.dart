import 'dart:math';
import 'dart:typed_data';

import 'package:cal_flutter_app/kvstore_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;

void main() async {
  await cal.RustLib.init();
  test("Android Provider can be loaded", () async {
    KVStore store = KVStore();

    var implConf = await cal.getDefaultConfig(
        getFn: store.get, storeFn: store.store, allKeysFn: store.allKeys);
    var provider = await cal.createProviderFromName(
        name: "ANDROID_PROVIDER", implConf: implConf);
    expect(provider, isNotNull);
  });

  test("KeyPair can be created and used for every spec", () async {
    KVStore store = KVStore();

    var implConf = await cal.getDefaultConfig(
        getFn: store.get, storeFn: store.store, allKeysFn: store.allKeys);
    var provider = await cal.createProviderFromName(
        name: "ANDROID_PROVIDER", implConf: implConf);
    expect(provider, isNotNull);

    var caps = await provider!.getCapabilities();

    for (var asymSpec in caps.supportedAsymSpec) {
      var handle = await provider.createKeyPair(
          spec: cal.KeyPairSpec(
              asymSpec: asymSpec,
              signingHash: const cal.CryptoHash_Sha2(cal.Sha2Bits.sha256)));
      expect(handle, isNotNull);

      var data = Uint8List(20);
      Random().fillBytes(data);

      var signature = await handle.signData(data: data);
      var verified =
          await handle.verifySignature(data: data, signature: signature);
      expect(verified, isTrue);

      var data2 = Uint8List(20);
      Random().fillBytes(data2);
      var verified2 =
          await handle.verifySignature(data: data2, signature: signature);
      expect(verified2, isFalse);
    }
  });
}

extension FillBytes on Random {
  void fillBytes(Uint8List data) {
    for (var i = 0; i < data.length; i++) {
      data[i] = nextInt(256);
    }
  }
}

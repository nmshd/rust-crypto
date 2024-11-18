import 'dart:math';
import 'dart:typed_data';

import 'package:cal_flutter_app/kvstore_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;

void main() async {
  await cal.RustLib.init();
  test("Android Provider is available", () async {
    var provider = await cal.getAllProviders();
    var present = provider.any((element) => element == "ANDROID_PROVIDER");
    expect(present, isTrue);
  });

  test("KeyPair can be created and used for every spec and every provider",
      () async {
    KVStore store = KVStore();

    var implConf = await cal.getDefaultConfig(
        getFn: store.get,
        storeFn: store.store,
        deleteFn: store.delete,
        allKeysFn: store.allKeys);

    var providers = await cal.getAllProviders();
    for (var providerName in providers) {
      store.clear();
      var provider = await cal.createProviderFromName(
          name: providerName, implConf: implConf);
      expect(provider, isNotNull);

      var caps = await provider!.getCapabilities();

      expect(caps, isNotNull);
      for (var asymSpec in caps!.supportedAsymSpec) {
        var handle = await provider.createKeyPair(
            spec: cal.KeyPairSpec(
                asymSpec: asymSpec,
                signingHash: const cal.CryptoHash_Sha2(cal.Sha2Bits.sha256)));
        expect(handle, isNotNull);
        expect(store.count(), 1);

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

        await handle.delete();
        expect(store.count(), 0);
      }
    }
  });

//   test("import key and encrypt with it", () async {
//     KVStore store = KVStore();

//     var implConf = await cal.getDefaultConfig(
//         getFn: store.get,
//         storeFn: store.store,
//         deleteFn: store.delete,
//         allKeysFn: store.allKeys);

//     var provider = await cal.createProviderFromName(
//         name: "ANDROID_PROVIDER", implConf: implConf);

//     expect(provider, isNotNull);

//     var key =
//         "27dba4d424b6f8eca2ce758afab11bb93357580a03c22476a87aac512dc82e3b";
//     var data =
//         "ddc90fe0be020000ee8f5419e09210d277b2d5abf649ae395c7b58d906e76991";
//   });
}

extension FillBytes on Random {
  void fillBytes(Uint8List data) {
    for (var i = 0; i < data.length; i++) {
      data[i] = nextInt(256);
    }
  }
}

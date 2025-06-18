import 'dart:math';
import 'dart:typed_data';

import 'package:cal_flutter_app/kvstore_service.dart';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;
import 'package:flutter_test/flutter_test.dart';

void main() async {
  await cal.RustLib.init();

  KVStore store = KVStore();
  var implConf = await cal.getDefaultConfig(
      getFn: store.get,
      storeFn: store.store,
      deleteFn: store.delete,
      allKeysFn: store.allKeys);

  implConf.additionalConfig
      .add(const cal.AdditionalConfig.storageConfigPass("testpass"));

  test("KeyPair can be created and used for every spec and every provider",
      () async {
    var providers = await cal.getAllProviders();
    for (var providerName in providers) {
      store.clear();
      var provider = await cal.createProviderFromName(
          name: providerName, implConf: implConf);
      expect(provider, isNotNull, reason: "expected $providerName");

      var caps = await provider!.getCapabilities();

      expect(caps, isNotNull);
      for (var asymSpec in caps!.supportedAsymSpec) {
        var handle = await provider.createKeyPair(
            spec: cal.KeyPairSpec(
                asymSpec: asymSpec,
                signingHash: cal.CryptoHash.sha2256,
                ephemeral: false,
                nonExportable: false));
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

  test("Key can be derived", () async {
    var providers = await cal.getAllProviders();
    for (var providerName in providers) {
      store.clear();
      var provider = await cal.createProviderFromName(
          name: providerName, implConf: implConf);
      expect(provider, isNotNull, reason: "expected $providerName");

      var caps = await provider!.getCapabilities();

      expect(caps, isNotNull);
      for (var cipher in caps!.supportedCiphers) {
        var handle = await provider.createKey(
            spec: cal.KeySpec(
                cipher: cipher,
                signingHash: cal.CryptoHash.sha2256,
                ephemeral: true,
                nonExportable: false));
        expect(handle, isNotNull);

        var data = Uint8List(20);
        Random().fillBytes(data);

        var derive_nonce = Uint8List(16);
        Random().fillBytes(data);

        print("starting deriving");

        var derived1 = await handle.deriveKey(nonce: derive_nonce);
        var derived2 = await handle.deriveKey(nonce: derive_nonce);

        var (ciphertext, nonce) = await derived1.encrypt(data: data);
        var plaintext =
            await derived2.decryptData(encryptedData: ciphertext, iv: nonce);
        expect(data, plaintext);
      }
    }
  });

  test("DH exchange", () async {
    var providers = await cal.getAllProviders();
    for (var providerName in providers) {
      store.clear();
      var provider = await cal.createProviderFromName(
          name: providerName, implConf: implConf);
      expect(provider, isNotNull, reason: "expected $providerName");

      const spec = cal.KeyPairSpec(
          asymSpec: cal.AsymmetricKeySpec.p256,
          signingHash: cal.CryptoHash.sha2256,
          ephemeral: true,
          nonExportable: true);

      var exchange1 = await provider!.startEphemeralDhExchange(spec: spec);
      var exchange2 = await provider.startEphemeralDhExchange(spec: spec);

      var exchange1PublicKey = await exchange1.getPublicKey();
      var exchange2PublicKey = await exchange2.getPublicKey();

      print("got public keys");

      try {
        var (rx1, tx1) = await exchange1.deriveClientSessionKeys(
            serverPk: exchange2PublicKey);
        print("rx1: $rx1, tx1: $tx1");
        var (rx2, tx2) = await exchange2.deriveServerSessionKeys(
            clientPk: exchange1PublicKey);

        print("rx2: $rx2, tx2: $tx2");
        expect(rx1, tx2, reason: "rx1 should match tx2");
        expect(tx1, rx2, reason: "tx1 should match rx2");
      } catch (e) {
        print("Error during DH exchange: $e");
        rethrow;
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

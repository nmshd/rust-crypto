import 'package:cal_flutter_app/kvstore_service.dart';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart';

KVStore store = KVStore();

Future<Provider> getDefaultProvider() async {
  var implConf = await getAndroidConfig(
      getFn: store.get, storeFn: store.store, allKeysFn: store.allKeys);
  var provider =
      await createProviderFromName(name: "AndroidProvider", implConf: implConf);
  return provider!;
}

Future<KeyPairHandle> getDefaultKeyPair(Provider provider) async {
  const asymSpec = AsymmetricKeySpec.rsa(KeyBits.bits2048);
  const signingHash = CryptoHash_Sha2(Sha2Bits.sha256);
  const spec = KeyPairSpec(asymSpec: asymSpec, signingHash: signingHash);

  var handle = provider.createKeyPair(spec: spec);
  return handle;
}

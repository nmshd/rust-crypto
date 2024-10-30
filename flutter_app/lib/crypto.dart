import 'package:cal_flutter_plugin/cal_flutter_plugin.dart';

Future<Provider> getDefaultProvider() async {
  var implConf = await getAndroidConfig();
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

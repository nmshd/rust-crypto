import 'dart:io';

import 'package:cal_flutter_app/kvstore_service.dart';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart';

KVStore store = KVStore();

Future<Provider> getDefaultProvider() async {
  String providerName;
  if (Platform.isAndroid) {
    providerName = "ANDROID_PROVIDER";
  } else if (Platform.isMacOS || Platform.isIOS) {
    providerName = "APPLE_SECURE_ENCLAVE";
  } else {
    providerName = "STUB_PROVIDER";
  }

  var implConf = await getDefaultConfig(
      getFn: store.get,
      storeFn: store.store,
      deleteFn: store.delete,
      allKeysFn: store.allKeys);
  var provider =
      await createProviderFromName(name: providerName, implConf: implConf);
  return provider!;
}

Future<Provider> getNamedProvider(String providerName, String hmacPass) async {
  var implConf = await getDefaultConfig(
      getFn: store.get,
      storeFn: store.store,
      deleteFn: store.delete,
      allKeysFn: store.allKeys);

  implConf.additionalConfig.add(AdditionalConfig.storageConfigPass(hmacPass));
  var provider =
      await createProviderFromName(name: providerName, implConf: implConf);
  return provider!;
}

import 'dart:typed_data';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;
import 'package:cal_flutter_plugin/src/rust/third_party/crypto_layer/common.dart' as rcal;

class CryptoProvider {
  Future<rcal.Provider> _provider = cal.getProvider();

  Future<KeyPairHandle> generateKeyPair() async {
    var kph = await cal.createKeyPair(provider: await _provider);
    return KeyPairHandle(kph);
  }
}

class KeyPairHandle {
  rcal.KeyPairHandle _kph;

  KeyPairHandle(this._kph);

  Future<Uint8List> sign(Uint8List data) {
    return cal.sign(keyPairHandle: _kph, data: data);
  }

  Future<bool> verify(Uint8List data, Uint8List signature) {
    return cal.verify(keyPairHandle: _kph, data: data, signature: signature);
  }
}

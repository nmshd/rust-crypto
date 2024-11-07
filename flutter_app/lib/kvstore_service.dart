import 'dart:collection';
import 'dart:ffi';
import 'dart:typed_data';

class KVStore {
  HashMap<String, Uint8List> inner = HashMap<String, Uint8List>();

  bool store(String key, Uint8List value) {
    inner.addAll({key: value});
    print("KVStore: Added $key");
    return true;
  }

  Uint8List? get(String key) {
    var ret = inner[key];
    if (ret == null) {
      print("KVStore: Getting $key: null");
    } else {
      print("KVStore: Getting $key: found");
    }
    return ret;
  }

  void delete(String key) {
    inner.remove(key);
  }

  List<String> allKeys() {
    return inner.entries.map((e) => e.key).toList();
  }

  int count() {
    return inner.length;
  }

  void clear() {
    inner.clear();
  }
}

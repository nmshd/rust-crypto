import 'dart:convert';
import 'dart:typed_data';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;
import 'package:flutter/material.dart';

class EncryptionPage extends StatefulWidget {
  const EncryptionPage({super.key, required this.provider});

  final Future<cal.Provider>? provider;

  @override
  State<StatefulWidget> createState() => _EncryptionPageState();
}

class _EncryptionPageState extends State<EncryptionPage> {
  cal.KeyHandle? _keyHandle;
  List<cal.Cipher> _ciphers = [];
  cal.Cipher? _cipherChoice;
  String? _encryptedData;
  String? _decryptedData;
  final TextEditingController _dataToEncryptController =
      TextEditingController();
  final TextEditingController _dataToDecryptController =
      TextEditingController();

  @override
  void initState() {
    super.initState();

    if (widget.provider != null) {
      widget.provider!
          .then((provider) => provider.getCapabilities())
          .then((caps) => caps?.supportedCiphers)
          .then((e) => {
                setState(() {
                  if (e != null) {
                    _ciphers = e.toList();
                  }
                })
              });
    }
  }

  void generateKey() async {
    if (_cipherChoice != null) {
      var spec = cal.KeySpec(
          cipher: _cipherChoice!,
          signingHash: const cal.CryptoHash.sha2(cal.Sha2Bits.sha256));
      var key = await (await widget.provider!).createKey(spec: spec);
      setState(() {
        _keyHandle = key;
      });
    }
  }

  Future<void> encryptData() async {
    Uint8List signature = await _keyHandle!.encryptData(
        data: Uint8List.fromList(_dataToEncryptController.text.codeUnits));

    setState(() {
      _encryptedData = base64Encode(signature);
    });
  }

  void moveDataToDecrypt() {
    setState(() {
      _dataToDecryptController.text = _encryptedData ?? '';
    });
  }

  Future<void> decryptData() async {
    Uint8List decryptedData = await _keyHandle!.decryptData(
        encryptedData:
            Uint8List.fromList(base64Decode(_dataToDecryptController.text)));
    setState(() {
      _decryptedData = String.fromCharCodes(decryptedData);
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(8),
      children: <Widget>[
        const Center(child: Text("Symmetric en- and decryption")),
        Container(
          margin: const EdgeInsets.only(left: 20.0, right: 20.0, bottom: 20.0),
          child: InputDecorator(
            decoration: InputDecoration(
              labelText: 'Key',
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10.0),
              ),
            ),
            child: Column(
              children: [
                DropdownMenu(
                  onSelected: (value) {
                    setState(() {
                      _cipherChoice = value;
                    });
                  },
                  dropdownMenuEntries:
                      _ciphers.map<DropdownMenuEntry<cal.Cipher>>((cipher) {
                    return DropdownMenuEntry<cal.Cipher>(
                      value: cipher,
                      label: cipher.toString(),
                      enabled: true,
                    );
                  }).toList(),
                ),
                ElevatedButton(
                  onPressed: generateKey,
                  child: const Text('Generate'),
                ),
              ],
            ),
          ),
        ),
        Visibility(
          visible: _keyHandle != null,
          child: Container(
            margin:
                const EdgeInsets.only(left: 20.0, right: 20.0, bottom: 20.0),
            child: InputDecorator(
              decoration: InputDecoration(
                labelText: 'Signing',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10.0),
                ),
              ),
              child: Column(
                children: [
                  TextField(
                    controller: _dataToEncryptController,
                    decoration: InputDecoration(
                      labelText: 'Data to encrypt',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10.0),
                      ),
                    ),
                  ),
                  Container(
                    margin: const EdgeInsets.only(top: 10.00),
                    child: InputDecorator(
                      decoration: InputDecoration(
                        labelText: 'encrypted',
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10.0),
                        ),
                      ),
                      child: Text(
                        _encryptedData ?? 'N/A',
                      ),
                    ),
                  ),
                  ElevatedButton(
                    onPressed: encryptData,
                    child: const Text('Encrypt'),
                  ),
                  ElevatedButton(
                    onPressed: moveDataToDecrypt,
                    child: const Text('Move to Decrypt'),
                  ),
                ],
              ),
            ),
          ),
        ),
        Visibility(
          visible: _keyHandle != null,
          child: Container(
            margin:
                const EdgeInsets.only(left: 20.0, right: 20.0, bottom: 20.0),
            child: InputDecorator(
              decoration: InputDecoration(
                labelText: 'Decryption',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10.0),
                ),
              ),
              child: Column(
                children: [
                  TextField(
                    controller: _dataToDecryptController,
                    decoration: InputDecoration(
                      labelText: 'Data to decrypt',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10.0),
                      ),
                    ),
                  ),
                  Container(
                    margin: const EdgeInsets.only(top: 10.00),
                    child: InputDecorator(
                      decoration: InputDecoration(
                        labelText: 'decrypted',
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10.0),
                        ),
                      ),
                      child: Text(
                        _decryptedData ?? 'N/A',
                      ),
                    ),
                  ),
                  ElevatedButton(
                    onPressed: decryptData,
                    child: const Text('Decrypt'),
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

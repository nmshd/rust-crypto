import 'dart:convert';
import 'dart:typed_data';
import 'package:cal_flutter_app/crypto.dart';
import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;
import 'package:flutter/material.dart';

void main() async {
  await cal.RustLib.init();
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        // This is the theme of your application.
        //
        // TRY THIS: Try running your application with "flutter run". You'll see
        // the application has a purple toolbar. Then, without quitting the app,
        // try changing the seedColor in the colorScheme below to Colors.green
        // and then invoke "hot reload" (save your changes or press the "hot
        // reload" button in a Flutter-supported IDE, or press "r" if you used
        // the command line to start the app).
        //
        // Notice that the counter didn't reset back to zero; the application
        // state is not lost during the reload. To reset the state, use hot
        // restart instead.
        //
        // This works for code too, not just values: Most code changes can be
        // tested with just a hot reload.
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class SigningPage extends StatefulWidget {
  const SigningPage({super.key, required this.provider});

  final cal.Provider provider;

  @override
  State<StatefulWidget> createState() => _SigningPageState();
}

class _SigningPageState extends State<SigningPage> {
  cal.KeyPairHandle? _keyPairHandle;
  List<cal.AsymmetricKeySpec> _algos = [];
  cal.AsymmetricKeySpec? _algoChoice;
  String? _signature;
  bool? _isVerified;
  final TextEditingController _dataToVerifyController = TextEditingController();
  final TextEditingController _dataToSignController = TextEditingController();
  final TextEditingController _signatureToVerifyController =
      TextEditingController();

  @override
  void initState() {
    super.initState();

    widget.provider
        .getCapabilities()
        .then((caps) => caps.supportedAsymSpec)
        .then((e) => {
              setState(() {
                _algos = e.toList();
              })
            });
  }

  void generateKey() {
    if (_algoChoice != null) {
      var spec = cal.KeyPairSpec(
          asymSpec: _algoChoice!,
          signingHash: const cal.CryptoHash.sha2(cal.Sha2Bits.sha256));
      widget.provider.createKeyPair(spec: spec).then((keyPair) {
        setState(() {
          _keyPairHandle = keyPair;
        });
      });
    }
  }

  Future<void> signData() async {
    Uint8List signature = await _keyPairHandle!.signData(
        data: Uint8List.fromList(_dataToSignController.text.codeUnits));

    setState(() {
      _signature = base64Encode(signature);
    });
  }

  void moveDataToVerify() {
    setState(() {
      _dataToVerifyController.text = _dataToSignController.text;
      _signatureToVerifyController.text = _signature ?? '';
    });
  }

  Future<void> verifyData() async {
    bool? isVerified = await _keyPairHandle!.verifySignature(
        data: Uint8List.fromList(_dataToVerifyController.text.codeUnits),
        signature: Uint8List.fromList(
            base64Decode(_signatureToVerifyController.text)));
    setState(() {
      _isVerified = isVerified;
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(8),
      children: <Widget>[
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
                      _algoChoice = value;
                    });
                  },
                  dropdownMenuEntries: _algos
                      .map<DropdownMenuEntry<cal.AsymmetricKeySpec>>((algo) {
                    return DropdownMenuEntry<cal.AsymmetricKeySpec>(
                      value: algo,
                      label: algo.toString(),
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
          visible: _keyPairHandle != null,
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
                    controller: _dataToSignController,
                    decoration: InputDecoration(
                      labelText: 'Data to sign',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10.0),
                      ),
                    ),
                  ),
                  Container(
                    margin: const EdgeInsets.only(top: 10.00),
                    child: InputDecorator(
                      decoration: InputDecoration(
                        labelText: 'Signature',
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10.0),
                        ),
                      ),
                      child: Text(
                        _signature ?? 'N/A',
                      ),
                    ),
                  ),
                  ElevatedButton(
                    onPressed: signData,
                    child: const Text('Sign'),
                  ),
                  ElevatedButton(
                    onPressed: moveDataToVerify,
                    child: const Text('Move to Verify'),
                  ),
                ],
              ),
            ),
          ),
        ),
        Visibility(
          visible: _keyPairHandle != null,
          child: Container(
            margin:
                const EdgeInsets.only(left: 20.0, right: 20.0, bottom: 20.0),
            child: InputDecorator(
              decoration: InputDecoration(
                labelText: 'Verification',
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10.0),
                ),
              ),
              child: Column(
                children: [
                  TextField(
                    controller: _dataToVerifyController,
                    decoration: InputDecoration(
                      labelText: 'Data to verify',
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10.0),
                      ),
                    ),
                  ),
                  Container(
                    margin: const EdgeInsets.only(top: 10.00),
                    child: TextField(
                      controller: _signatureToVerifyController,
                      decoration: InputDecoration(
                        labelText: 'Signature to verify',
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10.0),
                        ),
                      ),
                    ),
                  ),
                  ElevatedButton(
                    onPressed: verifyData,
                    child: const Text('Verify'),
                  ),
                  Text(
                    _isVerified == null
                        ? 'N/A'
                        : _isVerified!
                            ? 'Data is verified'
                            : 'Data is not verified',
                  )
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  // This widget is the home page of your application. It is stateful, meaning
  // that it has a State object (defined below) that contains fields that affect
  // how it looks.

  // This class is the configuration for the state. It holds the values (in this
  // case the title) provided by the parent (in this case the App widget) and
  // used by the build method of the State. Fields in a Widget subclass are
  // always marked "final".

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  late Future<cal.Provider> _cryptoProvider;

  @override
  void initState() {
    super.initState();

    _cryptoProvider = getDefaultProvider();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: FutureBuilder<cal.Provider>(
        future: _cryptoProvider,
        builder: (BuildContext context, AsyncSnapshot<cal.Provider> snapshot) {
          if (snapshot.hasData) {
            return SigningPage(provider: snapshot.data!);
          } else if (snapshot.hasError) {
            return Text("Error ${snapshot.error}");
          } else {
            return const Text("loading...");
          }
        },
      ),
    );
  }
}

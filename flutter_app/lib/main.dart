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
  late Future<cal.KeyPairHandle> _keyPairHandle;
  String? _signature;
  bool? _isVerified;
  final TextEditingController _dataToVerifyController = TextEditingController();
  final TextEditingController _dataToSignController = TextEditingController();
  final TextEditingController _signatureToVerifyController =
      TextEditingController();

  @override
  void initState() {
    super.initState();

    _cryptoProvider = getDefaultProvider();
    _keyPairHandle =
        _cryptoProvider.then((provider) => getDefaultKeyPair(provider));
  }

  Future<void> signData() async {
    Uint8List signature = await (await _keyPairHandle).signData(
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
    bool? isVerified = await (await _keyPairHandle).verifySignature(
        data: Uint8List.fromList(_dataToVerifyController.text.codeUnits),
        signature: Uint8List.fromList(
            base64Decode(_signatureToVerifyController.text)));
    setState(() {
      _isVerified = isVerified;
    });
  }

  @override
  Widget build(BuildContext context) {
    // This method is rerun every time setState is called, for instance as done
    // by the _incrementCounter method above.
    //
    // The Flutter framework has been optimized to make rerunning build methods
    // fast, so that you can just rebuild anything that needs updating rather
    // than having to individually change instances of widgets.
    return Scaffold(
      appBar: AppBar(
        // TRY THIS: Try changing the color here to a specific color (to
        // Colors.amber, perhaps?) and trigger a hot reload to see the AppBar
        // change color while the other colors stay the same.
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        // Here we take the value from the MyHomePage object that was created by
        // the App.build method, and use it to set our appbar title.
        title: Text(widget.title),
      ),
      body: Center(
        // Center is a layout widget. It takes a single child and positions it
        // in the middle of the parent.
        child: Column(
          // Column is also a layout widget. It takes a list of children and
          // arranges them vertically. By default, it sizes itself to fit its
          // children horizontally, and tries to be as tall as its parent.
          //
          // Column has various properties to control how it sizes itself and
          // how it positions its children. Here we use mainAxisAlignment to
          // center the children vertically; the main axis here is the vertical
          // axis because Columns are vertical (the cross axis would be
          // horizontal).
          //
          // TRY THIS: Invoke "debug painting" (choose the "Toggle Debug Paint"
          // action in the IDE, or press "p" in the console), to see the
          // wireframe for each widget.
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Container(
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
            Container(
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
          ],
        ),
      ),
    );
  }
}

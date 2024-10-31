import 'package:cal_flutter_app/encryption_page.dart';

import 'crypto.dart';
import 'signing_page.dart';
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

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> with TickerProviderStateMixin {
  late PageController _pageViewController;
  late TabController _tabController;

  late Future<cal.Provider> _cryptoProvider;

  @override
  void initState() {
    super.initState();

    _cryptoProvider = getDefaultProvider();
    _pageViewController = PageController();
    _tabController = TabController(length: 2, vsync: this);
  }

  void _handlePageViewChanged(int currentPageIndex) {
    _tabController.index = currentPageIndex;
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
            return PageView(
              controller: _pageViewController,
              onPageChanged: _handlePageViewChanged,
              children: <Widget>[
                SigningPage(provider: snapshot.data!),
                EncryptionPage(provider: snapshot.data!),
              ],
            );
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

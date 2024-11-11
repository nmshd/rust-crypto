import 'package:cal_flutter_plugin/cal_flutter_plugin.dart' as cal;
import 'package:flutter/material.dart';

class ProviderPage extends StatefulWidget {
  const ProviderPage({super.key, required this.setProvider});

  final Function(String) setProvider;

  @override
  State<StatefulWidget> createState() => _ProviderPageState();
}

class _ProviderPageState extends State<ProviderPage> {
  String? _providerChoice;
  List<String> _providerNames = [];

  @override
  void initState() {
    super.initState();

    cal.getAllProviders().then((names) {
      setState(() {
        _providerNames = names;
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.all(8),
      children: <Widget>[
        const Center(child: Text("Select Provider")),
        Container(
          margin: const EdgeInsets.only(left: 20.0, right: 20.0, bottom: 20.0),
          child: InputDecorator(
            decoration: InputDecoration(
              labelText: 'Provider',
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(10.0),
              ),
            ),
            child: Column(
              children: [
                DropdownMenu(
                  onSelected: (value) {
                    setState(() {
                      _providerChoice = value;
                    });
                  },
                  dropdownMenuEntries:
                      _providerNames.map<DropdownMenuEntry<String>>((name) {
                    return DropdownMenuEntry<String>(
                      value: name,
                      label: name,
                      enabled: true,
                    );
                  }).toList(),
                ),
                ElevatedButton(
                  onPressed: () {
                    widget.setProvider(_providerChoice!);
                  },
                  child: const Text('Select'),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

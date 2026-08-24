import 'package:flutter/material.dart';
import 'package:secure_keypad_flutter/secure_keypad_flutter.dart';

void main() {
  runApp(const SecureKeypadExampleApp());
}

class SecureKeypadExampleApp extends StatelessWidget {
  const SecureKeypadExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: ThemeData.dark(useMaterial3: true),
      home: const HangulKeypadPage(),
    );
  }
}

class HangulKeypadPage extends StatefulWidget {
  const HangulKeypadPage({super.key});

  @override
  State<HangulKeypadPage> createState() => _HangulKeypadPageState();
}

class _HangulKeypadPageState extends State<HangulKeypadPage> {
  final SecureKeypadController _controller = SecureKeypadController();
  late final SecureKeypadConfiguration _configuration;
  DisplayState _displayState = DisplayState.empty;
  SecureKeypadResultCode _result = SecureKeypadResultCode.cancelled;
  int _length = 0;

  KeypadLayout get _layout => const KeypadLayout(
    schemaVersion: 1,
    id: 'example-hangul',
    locale: 'ko',
    randomizeInputKeys: true,
    rows: <List<KeySpec>>[
      <KeySpec>[
        KeySpec(id: 'jamo-giyeok', label: 'ㄱ', role: KeyRole.input),
        KeySpec(id: 'jamo-nieun', label: 'ㄴ', role: KeyRole.input),
        KeySpec(id: 'jamo-digeut', label: 'ㄷ', role: KeyRole.input),
      ],
      <KeySpec>[
        KeySpec(id: 'vowel-a', label: 'ㅏ', role: KeyRole.input),
        KeySpec(id: 'vowel-eo', label: 'ㅓ', role: KeyRole.input),
        KeySpec(id: 'vowel-o', label: 'ㅗ', role: KeyRole.input),
      ],
      <KeySpec>[
        KeySpec(id: 'clear', label: '초기화', role: KeyRole.clear),
        KeySpec(id: 'backspace', label: '삭제', role: KeyRole.backspace),
        KeySpec(id: 'cancel', label: '취소', role: KeyRole.cancel),
        KeySpec(id: 'submit', label: '확인', role: KeyRole.submit),
      ],
    ],
  );

  @override
  void initState() {
    super.initState();
    _configuration = SecureKeypadConfiguration(
      layout: _layout,
      theme: SecureKeypadTheme.defaultTheme(),
      inputPolicy: InputPolicy.hangul,
      maxTokens: 32,
      timeoutMs: 120000,
      onMaskedStateChanged: (state) {
        if (!mounted) return;
        setState(() {
          _length = state.length;
          _displayState = state.displayState;
        });
      },
      onResult: (result) {
        if (!mounted) return;
        setState(() {
          _result = result;
        });
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Secure Native Hangul example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: <Widget>[
            Text('$_result · $_displayState · $_length masked characters'),
            const SizedBox(height: 16),
            Expanded(
              child: SecureKeypad(
                configuration: _configuration,
                controller: _controller,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

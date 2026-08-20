import 'package:flutter_test/flutter_test.dart';
import 'package:secure_keypad_flutter/secure_keypad.dart';

void main() {
  test('default numeric configuration is valid and contains no secret channel', () {
    final configuration = SecureKeypadConfiguration.defaultNumeric();

    expect(configuration.validate(), isEmpty);
    expect(configuration.inputPolicy, InputPolicy.numeric);
    expect(configuration.layout.rows.expand((row) => row).any((key) => key.role == KeyRole.input), isTrue);
    expect(configuration.onMaskedStateChanged, isNull);
    expect(configuration.onResult, isNull);
  });

  test('configuration rejects unsafe bounds and unsupported schema versions', () {
    final configuration = SecureKeypadConfiguration(
      layout: KeypadLayout(
        schemaVersion: 2,
        rows: <List<KeySpec>>[
          <KeySpec>[const KeySpec(id: 'digit-1', role: KeyRole.input)],
        ],
      ),
      theme: SecureKeypadTheme.defaultTheme(),
      maxTokens: 0,
      timeoutMs: 0,
    );

    expect(configuration.validate(), containsAll(<String>[
      'layout.schemaVersion is unsupported',
      'maxTokens is invalid',
      'timeoutMs is invalid',
    ]));
  });

  test('callbacks expose masked state and result codes only', () {
    final states = <MaskedState>[];
    final results = <SecureKeypadResultCode>[];
    final configuration = SecureKeypadConfiguration.defaultNumeric(
      onMaskedStateChanged: states.add,
      onResult: results.add,
    );

    configuration.onMaskedStateChanged!(const MaskedState(length: 2, displayState: DisplayState.masked));
    configuration.onResult!(SecureKeypadResultCode.success);

    expect(states.single.length, 2);
    expect(results.single, SecureKeypadResultCode.success);
  });
}

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

  test('ASCII policy remains a native-only policy', () {
    final configuration = SecureKeypadConfiguration(
      layout: SecureKeypadConfiguration.defaultNumeric().layout,
      theme: SecureKeypadTheme.defaultTheme(),
      inputPolicy: InputPolicy.ascii,
      maxTokens: 32,
    );

    expect(configuration.validate(), isEmpty);
    expect(configuration.toPlatformCreationParams()['inputPolicy'], 'ascii');
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

  test('platform creation params contain only public configuration', () {
    final configuration = SecureKeypadConfiguration.defaultNumeric();

    final params = configuration.toPlatformCreationParams();

    expect(params.keys, containsAll(<String>[
      'layout',
      'theme',
      'inputPolicy',
      'maxTokens',
      'timeoutMs',
    ]));
    expect(params.keys, isNot(contains('value')));
    expect(params.keys, isNot(contains('password')));
    expect(params.keys, isNot(contains('secret')));
    expect(params['inputPolicy'], 'numeric');
    expect((params['layout'] as Map<String, Object?>)['schemaVersion'], 1);
  });

  test('controller exposes only a native cancel command', () async {
    final controller = SecureKeypadController();

    await expectLater(
      controller.cancel(),
      throwsA(isA<StateError>()),
    );
  });

  test('masked state length is bounded at the framework event boundary', () {
    expect(isSecureKeypadRenderedLengthValid(0), isTrue);
    expect(isSecureKeypadRenderedLengthValid(4096), isTrue);
    expect(isSecureKeypadRenderedLengthValid(-1), isFalse);
    expect(isSecureKeypadRenderedLengthValid(4097), isFalse);
  });

  test('native events reject unexpected fields before parsing', () {
    expect(
      isSecureKeypadNativeEventShapeValid(<Object?, Object?>{
        'type': 'state',
        'length': 2,
        'displayState': 'masked',
      }),
      isTrue,
    );
    expect(
      isSecureKeypadNativeEventShapeValid(<Object?, Object?>{
        'type': 'state',
        'length': 2,
        'displayState': 'masked',
        'secret': 'fixture-only-secret',
      }),
      isFalse,
    );
    expect(
      isSecureKeypadNativeEventShapeValid(<Object?, Object?>{
        'type': 'result',
        'code': 'success',
        'value': 'fixture-only-secret',
      }),
      isFalse,
    );
  });

  test('rejects secret-bearing nested theme fields before bridge serialization', () {
    final baseTheme = SecureKeypadTheme.defaultTheme();
    final colors = Map<String, String>.of(baseTheme.colors)
      ..['secret'] = '#000000';
    final configuration = SecureKeypadConfiguration(
      layout: defaultNumericLayout,
      theme: SecureKeypadTheme(
        colors: colors,
        metrics: baseTheme.metrics,
        keyFontSize: baseTheme.keyFontSize,
        keyFontWeight: baseTheme.keyFontWeight,
        haptic: baseTheme.haptic,
        sound: baseTheme.sound,
        pressDurationMs: baseTheme.pressDurationMs,
        maskRevealDurationMs: baseTheme.maskRevealDurationMs,
      ),
    );

    expect(configuration.validate(), contains('theme.colors is invalid'));
    expect(
      () => configuration.toPlatformCreationParams(),
      throwsA(isA<ArgumentError>()),
    );
  });
}

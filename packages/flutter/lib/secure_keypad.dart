/// Public Flutter contract for the Secure Native keypad adapter.
///
/// This library deliberately has no `String value`, password getter, text
/// editing controller, or submit callback. Native/core code owns composition
/// and authentication handoff; Flutter receives masked state and result codes.
library secure_keypad_flutter;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

/// Native-only policies. Web custom keypads are intentionally not represented.
enum InputPolicy { numeric, ascii, hangul }

enum KeyRole { input, backspace, submit, clear, cancel, spacer }

enum LayoutDirection { ltr, rtl }

enum DisplayState { empty, masked, submitted, cancelled }

enum SecureKeypadResultCode { success, cancelled, invalid, locked, error }

/// Maximum masked length accepted at the Flutter/native event boundary.
const int secureKeypadMaxRenderedLength = 4096;

bool isSecureKeypadRenderedLengthValid(int length) =>
    length >= 0 && length <= secureKeypadMaxRenderedLength;

bool _hasSecureKeypadExactKeys(
  Map<Object?, Object?> event,
  Set<String> expected,
) {
  return event.length == expected.length &&
      event.keys.every((key) => key is String && expected.contains(key));
}

/// Rejects native event maps that contain secret-like or otherwise unsupported fields.
bool isSecureKeypadNativeEventShapeValid(Map<Object?, Object?> event) {
  final type = event['type'];
  if (type == 'state') {
    return _hasSecureKeypadExactKeys(event, <String>{'type', 'length', 'displayState'});
  }
  if (type == 'result') {
    return _hasSecureKeypadExactKeys(event, <String>{'type', 'code'});
  }
  return false;
}

typedef MaskedStateCallback = void Function(MaskedState state);
typedef ResultCallback = void Function(SecureKeypadResultCode result);

class KeySpec {
  const KeySpec({
    required this.id,
    required this.role,
    this.label,
    this.icon,
    this.accessibilityLabel,
    this.testId,
  });

  final String id;
  final KeyRole role;
  final String? label;
  final String? icon;
  final String? accessibilityLabel;
  final String? testId;
}

class KeypadLayout {
  const KeypadLayout({
    required this.schemaVersion,
    required this.rows,
    this.id,
    this.locale,
    this.direction = LayoutDirection.ltr,
    this.header = true,
    this.display = true,
    this.footer = true,
    this.error = true,
  });

  final int schemaVersion;
  final String? id;
  final String? locale;
  final LayoutDirection direction;
  final List<List<KeySpec>> rows;
  final bool header;
  final bool display;
  final bool footer;
  final bool error;
}

class SecureKeypadTheme {
  const SecureKeypadTheme({
    required this.colors,
    required this.metrics,
    required this.keyFontSize,
    this.keyFontWeight = 600,
    this.haptic = HapticFeedbackStyle.light,
    this.sound = SoundFeedback.none,
    this.pressDurationMs = 80,
    this.maskRevealDurationMs = 0,
  });

  final Map<String, String> colors;
  final Map<String, double> metrics;
  final double keyFontSize;
  final int keyFontWeight;
  final HapticFeedbackStyle haptic;
  final SoundFeedback sound;
  final int pressDurationMs;
  final int maskRevealDurationMs;

  static SecureKeypadTheme defaultTheme() => const SecureKeypadTheme(
        colors: <String, String>{
          'background': '#101114',
          'keyBackground': '#23262D',
          'keyForeground': '#FFFFFF',
          'keyPressedBackground': '#3B82F6',
          'keyDisabledBackground': '#4B5563',
          'error': '#F87171',
        },
        metrics: <String, double>{
          'keyHeight': 56,
          'keyGap': 8,
          'keyRadius': 12,
          'contentPadding': 16,
        },
      );
}

enum HapticFeedbackStyle { none, light, medium, heavy }

enum SoundFeedback { none, click }

class MaskedState {
  const MaskedState({required this.length, required this.displayState});

  final int length;
  final DisplayState displayState;
}

/// Non-secret commands for a mounted native keypad.
///
/// The controller never carries input. Its cancel operation asks the native
/// view to clear and zeroize the active session through a method channel.
class SecureKeypadController {
  Future<void> Function()? _cancelAction;

  /// Cancels the active native session and clears its pending input.
  Future<void> cancel() {
    final action = _cancelAction;
    if (action == null) {
      return Future<void>.error(
        StateError('SecureKeypadController is not attached to a native keypad'),
      );
    }
    return action();
  }

  void _attach(Future<void> Function() action) {
    _cancelAction = action;
  }

  void _detach() {
    _cancelAction = null;
  }
}

/// Flutter-facing configuration. It is safe to pass across a framework
/// boundary because it contains presentation and policy only, never input.
class SecureKeypadConfiguration {
  const SecureKeypadConfiguration({
    required this.layout,
    required this.theme,
    this.inputPolicy = InputPolicy.numeric,
    this.maxTokens = 4096,
    this.timeoutMs = 120000,
    this.onMaskedStateChanged,
    this.onResult,
  });

  factory SecureKeypadConfiguration.defaultNumeric({
    MaskedStateCallback? onMaskedStateChanged,
    ResultCallback? onResult,
  }) {
    return SecureKeypadConfiguration(
      layout: defaultNumericLayout,
      theme: SecureKeypadTheme.defaultTheme(),
      onMaskedStateChanged: onMaskedStateChanged,
      onResult: onResult,
    );
  }

  final KeypadLayout layout;
  final SecureKeypadTheme theme;
  final InputPolicy inputPolicy;
  final int maxTokens;
  final int timeoutMs;
  final MaskedStateCallback? onMaskedStateChanged;
  final ResultCallback? onResult;

  /// Converts public configuration to the native PlatformView creation map.
  ///
  /// This map intentionally has no callback, text, password, or secret field.
  /// The native plugin receives it once when the platform view is created.
  Map<String, Object?> toPlatformCreationParams() {
    return <String, Object?>{
      'layout': <String, Object?>{
        'schemaVersion': layout.schemaVersion,
        if (layout.id != null) 'id': layout.id,
        if (layout.locale != null) 'locale': layout.locale,
        'direction': layout.direction.name,
        'rows': layout.rows
            .map(
              (row) => row
                  .map(
                    (key) => <String, Object?>{
                      'id': key.id,
                      if (key.label != null) 'label': key.label,
                      if (key.icon != null) 'icon': key.icon,
                      'role': key.role.name,
                      if (key.accessibilityLabel != null)
                        'accessibilityLabel': key.accessibilityLabel,
                      if (key.testId != null) 'testId': key.testId,
                    },
                  )
                  .toList(growable: false),
            )
            .toList(growable: false),
        'slots': <String, Object?>{
          'header': layout.header,
          'display': layout.display,
          'footer': layout.footer,
          'error': layout.error,
        },
      },
      'theme': <String, Object?>{
        'schemaVersion': 1,
        'colors': Map<String, String>.of(theme.colors),
        'metrics': Map<String, double>.of(theme.metrics),
        'typography': <String, Object?>{
          'keyFontSize': theme.keyFontSize,
          'keyFontWeight': theme.keyFontWeight,
        },
        'animation': <String, Object?>{
          'pressDurationMs': theme.pressDurationMs,
          'maskRevealDurationMs': theme.maskRevealDurationMs,
        },
        'feedback': <String, Object?>{
          'haptic': theme.haptic.name,
          'sound': theme.sound.name,
        },
      },
      'inputPolicy': inputPolicy.name,
      'maxTokens': maxTokens,
      'timeoutMs': timeoutMs,
    };
  }

  /// Validates only public configuration. It never includes field values in
  /// error text, which keeps host logs from echoing arbitrary labels.
  List<String> validate() {
    final errors = <String>[];
    if (layout.schemaVersion != 1) errors.add('layout.schemaVersion is unsupported');
    if (layout.rows.isEmpty || layout.rows.length > 16) errors.add('layout.rows is invalid');
    for (var rowIndex = 0; rowIndex < layout.rows.length; rowIndex++) {
      final row = layout.rows[rowIndex];
      if (row.isEmpty || row.length > 32) {
        errors.add('layout.rows[$rowIndex] is invalid');
        continue;
      }
      for (var keyIndex = 0; keyIndex < row.length; keyIndex++) {
        final key = row[keyIndex];
        final path = 'layout.rows[$rowIndex][$keyIndex]';
        if (!_keyIdPattern.hasMatch(key.id)) errors.add('$path.id is invalid');
        if (key.label != null && key.label!.length > 16) errors.add('$path.label is invalid');
        if (key.icon != null && !_keyIdPattern.hasMatch(key.icon!)) errors.add('$path.icon is invalid');
        if (key.accessibilityLabel != null && key.accessibilityLabel!.length > 80) {
          errors.add('$path.accessibilityLabel is invalid');
        }
        if (key.testId != null && !_keyIdPattern.hasMatch(key.testId!)) errors.add('$path.testId is invalid');
      }
    }
    if (maxTokens < 1 || maxTokens > 4096) errors.add('maxTokens is invalid');
    if (timeoutMs < 1 || timeoutMs > 86400000) errors.add('timeoutMs is invalid');
    if (theme.keyFontSize <= 0 || theme.keyFontSize > 128) errors.add('theme.keyFontSize is invalid');
    if (theme.keyFontWeight != 400 && theme.keyFontWeight != 500 && theme.keyFontWeight != 600 && theme.keyFontWeight != 700) {
      errors.add('theme.keyFontWeight is invalid');
    }
    return errors;
  }
}

/// Flutter PlatformView wrapper for the native-only keypad.
///
/// The widget creates a native view with public layout/theme configuration and
/// listens to a per-view event channel containing masked state and result
/// codes. It has no Dart-side text buffer or secret callback.
class SecureKeypad extends StatefulWidget {
  const SecureKeypad({
    super.key,
    required this.configuration,
    this.controller,
    this.viewType = 'secure_keypad/native',
  });

  final SecureKeypadConfiguration configuration;
  final SecureKeypadController? controller;
  final String viewType;

  @override
  State<SecureKeypad> createState() => _SecureKeypadState();
}

class _SecureKeypadState extends State<SecureKeypad> {
  StreamSubscription<dynamic>? _eventSubscription;
  MethodChannel? _controlChannel;
  bool _reportedConfigurationError = false;

  @override
  void didUpdateWidget(covariant SecureKeypad oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.configuration != widget.configuration ||
        oldWidget.viewType != widget.viewType) {
      _eventSubscription?.cancel();
      _eventSubscription = null;
      _controlChannel = null;
      _reportedConfigurationError = false;
      _attachController();
    }
    if (oldWidget.controller != widget.controller) {
      oldWidget.controller?._detach();
      _attachController();
    }
  }

  @override
  void dispose() {
    _eventSubscription?.cancel();
    widget.controller?._detach();
    _controlChannel = null;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final errors = widget.configuration.validate();
    if (errors.isNotEmpty) {
      _emitOnce(SecureKeypadResultCode.invalid);
      return const SizedBox.shrink();
    }

    if (kIsWeb ||
        (defaultTargetPlatform != TargetPlatform.android &&
            defaultTargetPlatform != TargetPlatform.iOS)) {
      _emitOnce(SecureKeypadResultCode.error);
      return const SizedBox.shrink();
    }

    final params = widget.configuration.toPlatformCreationParams();
    final key = ValueKey<String>(
      '${widget.viewType}:${jsonEncode(params)}',
    );
    if (defaultTargetPlatform == TargetPlatform.android) {
      return AndroidView(
        key: key,
        viewType: widget.viewType,
        creationParams: params,
        creationParamsCodec: const StandardMessageCodec(),
        onPlatformViewCreated: _onPlatformViewCreated,
      );
    }
    return UiKitView(
      key: key,
      viewType: widget.viewType,
      creationParams: params,
      creationParamsCodec: const StandardMessageCodec(),
      onPlatformViewCreated: _onPlatformViewCreated,
    );
  }

  void _onPlatformViewCreated(int viewId) {
    _controlChannel = MethodChannel('secure_keypad/control/$viewId');
    _attachController();
    _eventSubscription?.cancel();
    _eventSubscription = EventChannel('secure_keypad/events/$viewId')
        .receiveBroadcastStream()
        .listen(_onNativeEvent, onError: (_, __) {
      _emitResult(SecureKeypadResultCode.error);
    });
  }

  void _attachController() {
    final controller = widget.controller;
    if (controller == null) return;
    controller._attach(() async {
      final channel = _controlChannel;
      if (channel == null) {
        throw StateError('SecureKeypad native view is not ready');
      }
      await channel.invokeMethod<void>('cancel');
    });
  }

  void _onNativeEvent(dynamic event) {
    if (event is! Map<Object?, Object?> ||
        !isSecureKeypadNativeEventShapeValid(event)) {
      _emitResult(SecureKeypadResultCode.error);
      return;
    }
    final type = event['type'];
    if (type == 'state') {
      final length = event['length'];
      final displayState = event['displayState'];
      if (length is! int ||
          !isSecureKeypadRenderedLengthValid(length) ||
          displayState is! String) {
        _emitResult(SecureKeypadResultCode.error);
        return;
      }
      final state = _displayStateFromName(displayState);
      if (state == null) {
        _emitResult(SecureKeypadResultCode.error);
        return;
      }
      widget.configuration.onMaskedStateChanged?.call(
        MaskedState(length: length, displayState: state),
      );
    } else if (type == 'result' && event['code'] is String) {
      final result = _resultFromName(event['code'] as String);
      if (result == null) {
        _emitResult(SecureKeypadResultCode.error);
        return;
      }
      _emitResult(result);
    } else {
      _emitResult(SecureKeypadResultCode.error);
    }
  }

  void _emitOnce(SecureKeypadResultCode result) {
    if (_reportedConfigurationError) return;
    _reportedConfigurationError = true;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _emitResult(result);
    });
  }

  void _emitResult(SecureKeypadResultCode result) {
    widget.configuration.onResult?.call(result);
  }

  DisplayState? _displayStateFromName(String value) {
    for (final state in DisplayState.values) {
      if (state.name == value) return state;
    }
    return null;
  }

  SecureKeypadResultCode? _resultFromName(String value) {
    for (final result in SecureKeypadResultCode.values) {
      if (result.name == value) return result;
    }
    return null;
  }
}

/// Native adapter seam. Implementations must keep key events and composition
/// in native/core code and emit only these two callback shapes to Flutter.
abstract interface class SecureKeypadNativeAdapter {
  void configure(SecureKeypadConfiguration configuration);

  void cancel();

  void dispose();
}

final RegExp _keyIdPattern = RegExp(r'^[a-z0-9][a-z0-9._-]{0,63}$');

const KeypadLayout defaultNumericLayout = KeypadLayout(
  schemaVersion: 1,
  id: 'default-numeric',
  locale: 'en',
  rows: <List<KeySpec>>[
    <KeySpec>[
      KeySpec(id: 'digit-1', label: '1', role: KeyRole.input),
      KeySpec(id: 'digit-2', label: '2', role: KeyRole.input),
      KeySpec(id: 'digit-3', label: '3', role: KeyRole.input),
    ],
    <KeySpec>[
      KeySpec(id: 'digit-4', label: '4', role: KeyRole.input),
      KeySpec(id: 'digit-5', label: '5', role: KeyRole.input),
      KeySpec(id: 'digit-6', label: '6', role: KeyRole.input),
    ],
    <KeySpec>[
      KeySpec(id: 'digit-7', label: '7', role: KeyRole.input),
      KeySpec(id: 'digit-8', label: '8', role: KeyRole.input),
      KeySpec(id: 'digit-9', label: '9', role: KeyRole.input),
    ],
    <KeySpec>[
      KeySpec(id: 'clear', label: 'Clear', role: KeyRole.clear),
      KeySpec(id: 'digit-0', label: '0', role: KeyRole.input),
      KeySpec(id: 'backspace', label: 'Delete', role: KeyRole.backspace),
    ],
    <KeySpec>[
      KeySpec(id: 'cancel', label: 'Cancel', role: KeyRole.cancel),
      KeySpec(id: 'submit', label: 'Continue', role: KeyRole.submit),
    ],
  ],
);

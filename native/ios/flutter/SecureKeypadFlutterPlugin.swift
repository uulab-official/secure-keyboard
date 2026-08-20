import Flutter
import Foundation
import UIKit

public enum SecureKeypadFlutterRegistration {
    public static let viewType = "secure_keypad/native"
    public static let eventChannelPrefix = "secure_keypad/events/"
}

public final class SecureKeypadFlutterPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let factory = SecureKeypadFlutterPlatformViewFactory(messenger: registrar.messenger())
        registrar.register(factory, withId: SecureKeypadFlutterRegistration.viewType)
    }
}

private final class SecureKeypadFlutterPlatformViewFactory: NSObject, FlutterPlatformViewFactory {
    private let messenger: FlutterBinaryMessenger

    init(messenger: FlutterBinaryMessenger) {
        self.messenger = messenger
    }

    func create(
        withFrame frame: CGRect,
        viewIdentifier viewId: Int64,
        arguments args: Any?
    ) -> FlutterPlatformView {
        SecureKeypadFlutterPlatformView(
            frame: frame,
            viewId: viewId,
            arguments: args,
            messenger: messenger
        )
    }
}

private final class SecureKeypadFlutterPlatformView: NSObject, FlutterPlatformView, FlutterStreamHandler {
    private let keypad: SecureKeypadView
    private let eventChannel: FlutterEventChannel
    private var eventSink: FlutterEventSink?

    init(frame: CGRect, viewId: Int64, arguments: Any?, messenger: FlutterBinaryMessenger) {
        keypad = SecureKeypadView(frame: frame)
        eventChannel = FlutterEventChannel(
            name: "\(SecureKeypadFlutterRegistration.eventChannelPrefix)\(viewId)",
            binaryMessenger: messenger
        )
        super.init()
        eventChannel.setStreamHandler(self)

        keypad.onMaskedStateChanged = { [weak self] length, displayState in
            self?.eventSink?([
                "type": "state",
                "length": length,
                "displayState": secureKeypadDisplayStateName(displayState),
            ])
        }
        keypad.onError = { [weak self] _ in
            self?.eventSink?(["type": "result", "code": "error"])
        }
        keypad.onSubmit = { [weak self] submission in
            submission.close()
            self?.eventSink?(["type": "result", "code": "success"])
        }

        guard let dictionary = arguments as? NSDictionary else {
            eventSink?(["type": "result", "code": "invalid"])
            return
        }
        do {
            let config = try SecureKeypadBridgeConfiguration(dictionary: dictionary)
            if config.inputPolicy == "hangul" {
                try keypad.configureHangul(
                    layout: config.layout,
                    theme: config.theme,
                    maxTokens: config.maxTokens,
                    timeoutMs: config.timeoutMs
                )
            } else {
                try keypad.configureNumeric(
                    layout: config.layout,
                    theme: config.theme,
                    maxTokens: config.maxTokens,
                    timeoutMs: config.timeoutMs
                )
            }
        } catch {
            eventSink?(["type": "result", "code": "invalid"])
        }
    }

    func view() -> UIView {
        keypad
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        eventSink = events
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        eventSink = nil
        return nil
    }

    deinit {
        eventChannel.setStreamHandler(nil)
        keypad.releaseSession()
    }
}

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
    private var pendingEvent: [String: Any]?

    init(frame: CGRect, viewId: Int64, arguments: Any?, messenger: FlutterBinaryMessenger) {
        keypad = SecureKeypadView(frame: frame)
        eventChannel = FlutterEventChannel(
            name: "\(SecureKeypadFlutterRegistration.eventChannelPrefix)\(viewId)",
            binaryMessenger: messenger
        )
        super.init()
        eventChannel.setStreamHandler(self)

        keypad.onMaskedStateChanged = { [weak self] length, displayState in
            self?.emit([
                "type": "state",
                "length": length,
                "displayState": secureKeypadDisplayStateName(displayState),
            ])
            if displayState == 3 {
                self?.emit(["type": "result", "code": "cancelled"])
            }
        }
        keypad.onError = { [weak self] _ in
            self?.emit(["type": "result", "code": "error"])
        }
        keypad.onSubmit = { [weak self] submission in
            if SecureKeypadNativeSubmissionRouter.deliver(submission) {
                self?.emit(["type": "result", "code": "success"])
            } else {
                submission.close()
                self?.emit(["type": "result", "code": "error"])
            }
        }

        guard let dictionary = arguments as? NSDictionary else {
            emit(["type": "result", "code": "invalid"])
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
            emit(["type": "result", "code": "invalid"])
        }
    }

    func view() -> UIView {
        keypad
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        eventSink = events
        if let pendingEvent {
            events(pendingEvent)
            self.pendingEvent = nil
        }
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        eventSink = nil
        return nil
    }

    private func emit(_ event: [String: Any]) {
        if let eventSink {
            eventSink(event)
        } else {
            pendingEvent = event
        }
    }

    deinit {
        eventChannel.setStreamHandler(nil)
        keypad.releaseSession()
    }
}

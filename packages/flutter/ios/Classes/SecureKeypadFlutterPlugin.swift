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

    func createArgsCodec() -> FlutterMessageCodec & NSObjectProtocol {
        FlutterStandardMessageCodec.sharedInstance()
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
    private let controlChannel: FlutterMethodChannel
    private var eventSink: FlutterEventSink?
    private var pendingEvents: [[String: Any]] = []

    init(frame: CGRect, viewId: Int64, arguments: Any?, messenger: FlutterBinaryMessenger) {
        keypad = SecureKeypadView(frame: frame)
        eventChannel = FlutterEventChannel(
            name: "\(SecureKeypadFlutterRegistration.eventChannelPrefix)\(viewId)",
            binaryMessenger: messenger
        )
        controlChannel = FlutterMethodChannel(
            name: "secure_keypad/control/\(viewId)",
            binaryMessenger: messenger
        )
        super.init()
        eventChannel.setStreamHandler(self)
        controlChannel.setMethodCallHandler { [weak self] call, result in
            switch call.method {
            case "cancel":
                self?.keypad.cancelSession()
                result(nil)
            case "pressKey":
                self?.requestHeadlessKeyPress(call.arguments, result: result)
            default:
                result(FlutterMethodNotImplemented)
            }
        }

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
        let nativeKeypad = keypad
        keypad.onSubmit = { [weak self, weak nativeKeypad] submission in
            guard let nativeKeypad else {
                submission.close()
                return
            }
            if SecureKeypadNativeSubmissionRouter.deliver(submission, from: nativeKeypad) {
                self?.emit(["type": "result", "code": "success"])
            } else {
                submission.close()
                self?.emit(["type": "result", "code": "error"])
            }
        }

        guard let dictionary = Self.dictionary(arguments) else {
            emit(["type": "result", "code": "invalid"])
            return
        }
        let config: SecureKeypadBridgeConfiguration
        do {
            config = try SecureKeypadBridgeConfiguration(dictionary: dictionary)
        } catch {
            emit(["type": "result", "code": "invalid"])
            return
        }
        do {
            keypad.setRendererMode(
                mode: config.mode,
                acknowledgeLowerAssurance: config.acknowledgeLowerAssurance
            )
            if config.inputPolicy == "hangul" {
                try keypad.configureHangul(
                    layout: config.layout,
                    theme: config.theme,
                    maxTokens: config.maxTokens,
                    timeoutMs: config.timeoutMs
                )
            } else if config.inputPolicy == "ascii" {
                try keypad.configureAscii(
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
            if let command = config.headlessKeyPress {
                keypad.requestHeadlessKeyPress(requestId: command.token, keyId: command.keyId)
            }
        } catch {
            emit(["type": "result", "code": "error"])
        }
    }

    func view() -> UIView {
        keypad
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        eventSink = events
        while !pendingEvents.isEmpty {
            events(pendingEvents.removeFirst())
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
            return
        }
        if event["type"] as? String == "state",
           pendingEvents.last?["type"] as? String == "state" {
            pendingEvents.removeLast()
        }
        if pendingEvents.count >= Self.maxPendingEvents {
            if let stateIndex = pendingEvents.firstIndex(where: { $0["type"] as? String == "state" }) {
                pendingEvents.remove(at: stateIndex)
            } else {
                pendingEvents.removeFirst()
            }
        }
        pendingEvents.append(event)
    }

    private func requestHeadlessKeyPress(_ arguments: Any?, result: @escaping FlutterResult) {
        guard let dictionary = arguments as? NSDictionary,
              dictionary.count == 2,
              Set(dictionary.allKeys.compactMap { $0 as? String }) == ["token", "keyId"],
              let rawToken = dictionary["token"] as? NSNumber,
              String(cString: rawToken.objCType) != "c",
              let keyId = dictionary["keyId"] as? String else {
            result(FlutterError(code: "invalid", message: nil, details: nil))
            return
        }
        let tokenValue = rawToken.doubleValue
        guard tokenValue.isFinite,
              tokenValue >= 0,
              tokenValue <= 9_007_199_254_740_991,
              tokenValue.rounded(.towardZero) == tokenValue,
              keyId.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            result(FlutterError(code: "invalid", message: nil, details: nil))
            return
        }
        keypad.requestHeadlessKeyPress(requestId: Int64(tokenValue), keyId: keyId)
        result(nil)
    }

    deinit {
        eventChannel.setStreamHandler(nil)
        controlChannel.setMethodCallHandler(nil)
        keypad.clearBridgeCallbacks()
        keypad.releaseSession()
    }

    private static func dictionary(_ value: Any?) -> NSDictionary? {
        guard let value else { return nil }
        if let dictionary = value as? NSDictionary {
            return dictionary
        }
        if let dictionary = value as? [String: Any] {
            return dictionary as NSDictionary
        }
        if let dictionary = value as? [String: AnyObject] {
            return dictionary as NSDictionary
        }
        if let dictionary = value as? [AnyHashable: Any] {
            return dictionary as NSDictionary
        }
        if let dictionary = value as? [AnyHashable: AnyObject] {
            return dictionary as NSDictionary
        }
        return nil
    }

    private static let maxPendingEvents = 32
}

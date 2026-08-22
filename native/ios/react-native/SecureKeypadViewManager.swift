import Foundation
import React

@objc(SecureKeypadReactView)
final class SecureKeypadReactView: SecureKeypadView {
    @objc var layout: NSDictionary? { didSet { configureIfReady() } }
    @objc var theme: NSDictionary? { didSet { configureIfReady() } }
    @objc var inputPolicy: NSString = "numeric" { didSet { configureIfReady() } }
    @objc var mode: NSString = "secure-native" { didSet { configureIfReady() } }
    @objc var acknowledgeLowerAssurance: NSNumber = false { didSet { configureIfReady() } }
    @objc var maxTokens: NSNumber = 8 { didSet { configureIfReady() } }
    @objc var timeoutMs: NSNumber = 60_000 { didSet { configureIfReady() } }
    @objc var cancelRequest: NSNumber? { didSet { requestCancelIfValid() } }
    @objc var headlessKeyPress: NSDictionary? { didSet { configureIfReady(forceHeadlessCommand: true) } }
    @objc var onMaskedStateChange: RCTBubblingEventBlock?
    @objc var onResult: RCTBubblingEventBlock?

    private var configuredFingerprint: String?

    override init(frame: CGRect) {
        super.init(frame: frame)
        installBridgeCallbacks()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        installBridgeCallbacks()
    }

    private func installBridgeCallbacks() {
        onSessionNeedsReconfiguration = { [weak self] in self?.configureIfReady() }
        onMaskedStateChanged = { [weak self] length, displayState in
            self?.onMaskedStateChange?([
                "length": length,
                "displayState": secureKeypadDisplayStateName(displayState),
            ])
            if displayState == 3 {
                self?.onResult?(["type": "result", "code": "cancelled"])
            }
        }
        onError = { [weak self] _ in
            self?.onResult?(["type": "result", "code": "error"])
        }
        onSubmit = { [weak self] submission in
            guard let view = self else {
                submission.close()
                return
            }
            if SecureKeypadNativeSubmissionRouter.deliver(submission, from: view) {
                view.onResult?(["type": "result", "code": "success"])
            } else {
                submission.close()
                view.onResult?(["type": "result", "code": "error"])
            }
        }
    }

    private func requestCancelIfValid() {
        guard let cancelRequest else { return }
        let value = cancelRequest.int64Value
        guard value >= 0, NSNumber(value: value) == cancelRequest else {
            onResult?(["type": "result", "code": "invalid"])
            return
        }
        requestCancel(value)
    }

    private func configureIfReady(forceHeadlessCommand: Bool = false) {
        guard let layout, let theme else {
            configuredFingerprint = nil
            releaseSession()
            return
        }
        var config: [String: Any] = [
            "layout": layout,
            "theme": theme,
            "inputPolicy": inputPolicy,
            "mode": mode,
            "acknowledgeLowerAssurance": acknowledgeLowerAssurance,
            "maxTokens": maxTokens,
            "timeoutMs": timeoutMs,
        ]
        if forceHeadlessCommand, let headlessKeyPress { config["headlessKeyPress"] = headlessKeyPress }
        let configDictionary = config as NSDictionary
        let fingerprint = "\(layout)\n\(theme)\n\(inputPolicy)\n\(mode)\n\(acknowledgeLowerAssurance)\n\(maxTokens)\n\(timeoutMs)"
        if fingerprint == configuredFingerprint && hasActiveSession {
            guard forceHeadlessCommand else { return }
            do {
                if let command = try SecureKeypadBridgeConfiguration(dictionary: configDictionary).headlessKeyPress {
                    requestHeadlessKeyPress(requestId: command.token, keyId: command.keyId)
                }
            } catch {
                onResult?(["type": "result", "code": "invalid"])
            }
            return
        }
        configuredFingerprint = fingerprint
        do {
            let parsed = try SecureKeypadBridgeConfiguration(dictionary: configDictionary)
            setRendererMode(mode: parsed.mode, acknowledgeLowerAssurance: parsed.acknowledgeLowerAssurance)
            if parsed.inputPolicy == "hangul" {
                try configureHangul(
                    layout: parsed.layout,
                    theme: parsed.theme,
                    maxTokens: parsed.maxTokens,
                    timeoutMs: parsed.timeoutMs
                )
            } else if parsed.inputPolicy == "ascii" {
                try configureAscii(
                    layout: parsed.layout,
                    theme: parsed.theme,
                    maxTokens: parsed.maxTokens,
                    timeoutMs: parsed.timeoutMs
                )
            } else {
                try configureNumeric(
                    layout: parsed.layout,
                    theme: parsed.theme,
                    maxTokens: parsed.maxTokens,
                    timeoutMs: parsed.timeoutMs
                )
            }
            if let command = parsed.headlessKeyPress {
                requestHeadlessKeyPress(requestId: command.token, keyId: command.keyId)
            }
        } catch {
            configuredFingerprint = nil
            onResult?(["type": "result", "code": "invalid"])
        }
    }

}

@objc(SecureKeypadViewManager)
final class SecureKeypadViewManager: RCTViewManager {
    override func view() -> UIView! {
        SecureKeypadReactView(frame: .zero)
    }

    @objc override static func requiresMainQueueSetup() -> Bool {
        true
    }
}

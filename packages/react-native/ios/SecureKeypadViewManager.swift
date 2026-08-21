import Foundation
import React

@objc(SecureKeypadReactView)
final class SecureKeypadReactView: SecureKeypadView {
    @objc var layout: NSDictionary? { didSet { configureIfReady() } }
    @objc var theme: NSDictionary? { didSet { configureIfReady() } }
    @objc var inputPolicy: NSString = "numeric" { didSet { configureIfReady() } }
    @objc var maxTokens: NSNumber = 8 { didSet { configureIfReady() } }
    @objc var timeoutMs: NSNumber = 60_000 { didSet { configureIfReady() } }
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
        onMaskedStateChanged = { [weak self] length, displayState in
            self?.onMaskedStateChange?([
                "length": length,
                "displayState": secureKeypadDisplayStateName(displayState),
            ])
        }
        onError = { [weak self] _ in
            self?.onResult?(["type": "result", "code": "error"])
        }
        onSubmit = { [weak self] submission in
            if SecureKeypadNativeSubmissionRouter.deliver(submission) {
                self?.onResult?(["type": "result", "code": "success"])
            } else {
                submission.close()
                self?.onResult?(["type": "result", "code": "error"])
            }
        }
    }

    private func configureIfReady() {
        guard let layout, let theme else { return }
        let config: NSDictionary = [
            "layout": layout,
            "theme": theme,
            "inputPolicy": inputPolicy,
            "maxTokens": maxTokens,
            "timeoutMs": timeoutMs,
        ]
        let fingerprint = "\(layout)\n\(theme)\n\(inputPolicy)\n\(maxTokens)\n\(timeoutMs)"
        guard fingerprint != configuredFingerprint else { return }
        configuredFingerprint = fingerprint
        do {
            let parsed = try SecureKeypadBridgeConfiguration(dictionary: config)
            if parsed.inputPolicy == "hangul" {
                try configureHangul(
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

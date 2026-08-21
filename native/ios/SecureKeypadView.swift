import Foundation
import SecureKeypadFFI
import UIKit

/// Converts the ABI display state to the framework-neutral string contract.
func secureKeypadDisplayStateName(_ value: UInt32) -> String {
    switch value {
    case 0: return "empty"
    case 1: return "masked"
    case 2: return "submitted"
    case 3: return "cancelled"
    default: return "empty"
    }
}

/// Public presentation role. It never contains a secret value.
public enum SecureKeyRole: String {
    case input
    case backspace
    case clear
    case submit
    case cancel
    case spacer
}

/// A public key specification supplied by the host application.
public struct SecureKeySpec {
    public let id: String
    public let label: String
    public let role: SecureKeyRole
    public let accessibilityLabel: String

    public init(id: String, label: String, role: SecureKeyRole, accessibilityLabel: String? = nil) {
        self.id = id
        self.label = label
        self.role = role
        self.accessibilityLabel = accessibilityLabel ?? label
    }
}

/// A row-based presentation layout with public IDs only.
public struct SecureKeypadLayout {
    public let rows: [[SecureKeySpec]]

    public init(rows: [[SecureKeySpec]]) {
        self.rows = rows
    }
}

/// Theme values for the native renderer.
public struct SecureKeypadTheme {
    public var backgroundColor: UIColor = UIColor(red: 16 / 255, green: 17 / 255, blue: 20 / 255, alpha: 1)
    public var keyColor: UIColor = UIColor(red: 35 / 255, green: 38 / 255, blue: 45 / 255, alpha: 1)
    public var keyPressedColor: UIColor = UIColor(red: 59 / 255, green: 130 / 255, blue: 246 / 255, alpha: 1)
    public var keyTextColor: UIColor = .white
    public var keyHeight: CGFloat = 56
    public var keyGap: CGFloat = 8
    public var keyRadius: CGFloat = 12
    public var contentPadding: CGFloat = 16
    public var keyFontSize: CGFloat = 24
    public var keyFontWeight: UIFont.Weight = .semibold

    public init() {}
}

private enum SecureKeypadInputPolicy {
    case numeric
    case ascii
    case hangul
}

/// Native-owned opaque submission. It cannot be serialized to JavaScript.
public final class SecureKeypadSubmission {
    fileprivate var raw: OpaquePointer?

    fileprivate init(raw: OpaquePointer) {
        self.raw = raw
    }

    /// Releases the native submission and zeroizes its secret buffer.
    public func close() {
        if let raw {
            secure_keypad_submission_free(raw)
            self.raw = nil
        }
    }

    /// Transfers the opaque capability to an installed native authentication
    /// consumer. The returned pointer is not a secret accessor and must be
    /// consumed by the matching native FFI layer or released exactly once.
    public func takeOpaqueHandle() -> OpaquePointer? {
        let value = raw
        raw = nil
        return value
    }

    deinit {
        close()
    }
}

/// Native-only handoff registry for framework adapters.
///
/// A host app may install a consumer that passes the opaque capability to its
/// native authentication client. The registry is never serialized to
/// JavaScript or Dart. If no consumer is installed, framework bridges must
/// release the submission instead of reporting a false success.
public enum SecureKeypadNativeSubmissionRouter {
    public typealias Consumer = (SecureKeypadSubmission) -> Bool

    private static let lock = NSLock()
    private static var consumer: Consumer?

    /// Installs the native-only consumer and replaces any previous consumer.
    public static func install(consumer: @escaping Consumer) {
        lock.lock()
        self.consumer = consumer
        lock.unlock()
    }

    /// Removes the native-only consumer.
    public static func clear() {
        lock.lock()
        consumer = nil
        lock.unlock()
    }

    static func deliver(_ submission: SecureKeypadSubmission) -> Bool {
        lock.lock()
        let current = consumer
        lock.unlock()
        return current?(submission) ?? false
    }
}

/// Non-secret native renderer errors.
public enum SecureKeypadViewError: Error {
    case invalidLayout
    case nativeFailure(UInt32)
}

/// Secure Native iOS keypad.
///
/// The view never creates an editable text control. Key IDs are sent to the Rust C ABI,
/// and only masked length/state are rendered. The submission callback remains
/// native-only and must not be bridged to JavaScript or Dart.
public class SecureKeypadView: UIView {
    private var session: OpaquePointer?
    private let displayLabel = UILabel()
    private let keypadStack = UIStackView()
    private let rootContainer = UIStackView()
    private var theme = SecureKeypadTheme()
    private var protectedPresentation = false
    private var notificationTokens: [NSObjectProtocol] = []
    private var contentPaddingConstraints: [NSLayoutConstraint] = []
    private var lastCancelRequest: Int64?

    /// Called with a native-only submission that the host must close or authenticate natively.
    public var onSubmit: ((SecureKeypadSubmission) -> Void)?

    /// Called with a public, non-secret native error code.
    public var onError: ((UInt32) -> Void)?

    /// Called with masked length and non-secret display state only.
    public var onMaskedStateChanged: ((UInt32, UInt32) -> Void)?

    public override init(frame: CGRect) {
        super.init(frame: frame)
        installViews()
        installProtectionObservers()
    }

    public required init?(coder: NSCoder) {
        super.init(coder: coder)
        installViews()
        installProtectionObservers()
    }

    deinit {
        notificationTokens.forEach(NotificationCenter.default.removeObserver)
        if let session {
            secure_keypad_session_free(session)
        }
    }

    public override func didMoveToWindow() {
        super.didMoveToWindow()
        refreshProtectionState()
    }

    /// Starts a numeric Secure Native session and renders the supplied layout.
    public func configureNumeric(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme = SecureKeypadTheme(),
        maxTokens: Int = 8,
        timeoutMs: UInt64 = 60_000
    ) throws {
        try configure(layout: layout, theme: theme, maxTokens: maxTokens, timeoutMs: timeoutMs, policy: .numeric)
    }

    /// Starts a printable-ASCII Secure Native session.
    public func configureAscii(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme = SecureKeypadTheme(),
        maxTokens: Int = 32,
        timeoutMs: UInt64 = 60_000
    ) throws {
        try configure(layout: layout, theme: theme, maxTokens: maxTokens, timeoutMs: timeoutMs, policy: .ascii)
    }

    /// Starts a structured Hangul Secure Native session.
    public func configureHangul(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme = SecureKeypadTheme(),
        maxTokens: Int = 32,
        timeoutMs: UInt64 = 60_000
    ) throws {
        try configure(layout: layout, theme: theme, maxTokens: maxTokens, timeoutMs: timeoutMs, policy: .hangul)
    }

    private func configure(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme,
        maxTokens: Int,
        timeoutMs: UInt64,
        policy: SecureKeypadInputPolicy
    ) throws {
        guard maxTokens > 0, maxTokens <= 4_096, timeoutMs > 0, timeoutMs <= 86_400_000 else {
            throw SecureKeypadViewError.invalidLayout
        }
        try validate(layout: layout)

        if let session {
            secure_keypad_session_free(session)
        }
        var newSession: OpaquePointer?
        let status: UInt32
        switch policy {
        case .numeric:
            status = secure_keypad_session_new_numeric(UInt32(maxTokens), timeoutMs, &newSession)
        case .ascii:
            status = secure_keypad_session_new_ascii(UInt32(maxTokens), timeoutMs, &newSession)
        case .hangul:
            status = secure_keypad_session_new_hangul(UInt32(maxTokens), timeoutMs, &newSession)
        }
        guard status == 0, let newSession else {
            throw SecureKeypadViewError.nativeFailure(status)
        }
        session = newSession
        self.theme = theme
        rootContainer.spacing = theme.keyGap
        keypadStack.spacing = theme.keyGap
        if contentPaddingConstraints.count == 4 {
            contentPaddingConstraints[0].constant = theme.contentPadding
            contentPaddingConstraints[1].constant = -theme.contentPadding
            contentPaddingConstraints[2].constant = theme.contentPadding
            contentPaddingConstraints[3].constant = -theme.contentPadding
        }
        displayLabel.font = .systemFont(ofSize: theme.keyFontSize, weight: theme.keyFontWeight)
        render(layout: layout)
        refreshMaskedState()
    }

    /// Releases the native session and zeroizes pending input.
    public func releaseSession() {
        if let session {
            secure_keypad_session_free(session)
            self.session = nil
        }
    }

    /// Cancels the native session and zeroizes any pending input.
    public func cancelSession() {
        guard let session else { return }
        let status = secure_keypad_session_cancel(session)
        if status != 0 {
            onError?(status)
        }
        refreshMaskedState()
    }

    /// Applies a monotonic, non-secret host command exactly once.
    public func requestCancel(_ requestId: Int64) {
        guard requestId >= 0 else {
            onError?(1)
            return
        }
        let previous = lastCancelRequest
        lastCancelRequest = requestId
        if let previous, previous != requestId {
            cancelSession()
        }
    }

    private func installViews() {
        backgroundColor = theme.backgroundColor
        displayLabel.textAlignment = .center
        displayLabel.font = .monospacedSystemFont(ofSize: 24, weight: .semibold)
        displayLabel.accessibilityTraits = .updatesFrequently
        displayLabel.accessibilityLabel = "No input"

        keypadStack.axis = .vertical
        keypadStack.alignment = .fill
        keypadStack.distribution = .fillEqually
        keypadStack.spacing = theme.keyGap

        rootContainer.axis = .vertical
        rootContainer.spacing = theme.keyGap
        rootContainer.addArrangedSubview(displayLabel)
        rootContainer.addArrangedSubview(keypadStack)
        rootContainer.translatesAutoresizingMaskIntoConstraints = false
        addSubview(rootContainer)
        contentPaddingConstraints = [
            rootContainer.leadingAnchor.constraint(equalTo: leadingAnchor, constant: theme.contentPadding),
            rootContainer.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -theme.contentPadding),
            rootContainer.topAnchor.constraint(equalTo: topAnchor, constant: theme.contentPadding),
            rootContainer.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -theme.contentPadding),
        ]
        NSLayoutConstraint.activate(contentPaddingConstraints + [
            displayLabel.heightAnchor.constraint(equalToConstant: 72),
        ])
    }

    private func render(layout: SecureKeypadLayout) {
        keypadStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        backgroundColor = theme.backgroundColor
        for row in layout.rows {
            let rowStack = UIStackView()
            rowStack.axis = .horizontal
            rowStack.alignment = .fill
            rowStack.distribution = .fillEqually
            rowStack.spacing = theme.keyGap
            for key in row {
                let button = UIButton(type: .system)
                let buttonTheme = theme
                button.setTitle(key.label, for: .normal)
                button.titleLabel?.font = .systemFont(ofSize: buttonTheme.keyFontSize, weight: buttonTheme.keyFontWeight)
                var configuration = UIButton.Configuration.filled()
                configuration.baseForegroundColor = buttonTheme.keyTextColor
                configuration.baseBackgroundColor = buttonTheme.keyColor
                configuration.cornerStyle = .medium
                button.configuration = configuration
                button.configurationUpdateHandler = { button in
                    guard var configuration = button.configuration else { return }
                    configuration.baseBackgroundColor = button.isHighlighted
                        ? buttonTheme.keyPressedColor
                        : buttonTheme.keyColor
                    button.configuration = configuration
                    button.layer.cornerRadius = buttonTheme.keyRadius
                }
                button.accessibilityLabel = key.accessibilityLabel
                button.accessibilityIdentifier = key.id
                button.addAction(UIAction { [weak self] _ in
                    self?.activate(key: key)
                }, for: .touchUpInside)
                rowStack.addArrangedSubview(button)
            }
            rowStack.heightAnchor.constraint(equalToConstant: theme.keyHeight).isActive = true
            keypadStack.addArrangedSubview(rowStack)
        }
    }

    private func activate(key: SecureKeySpec) {
        guard let session else { return }
        let status: UInt32
        switch key.role {
        case .input:
            let bytes = Array(key.id.utf8)
            status = bytes.withUnsafeBufferPointer { buffer in
                secure_keypad_session_press_key(session, buffer.baseAddress, buffer.count)
            }
        case .backspace:
            status = secure_keypad_session_backspace(session)
        case .clear:
            status = secure_keypad_session_clear(session)
        case .submit:
            var rawSubmission: OpaquePointer?
            status = secure_keypad_session_submit(session, &rawSubmission)
            if status == 0, let rawSubmission {
                let submission = SecureKeypadSubmission(raw: rawSubmission)
                if let onSubmit {
                    onSubmit(submission)
                } else {
                    submission.close()
                }
            }
        case .cancel:
            status = secure_keypad_session_cancel(session)
        case .spacer:
            return
        }
        if status != 0 {
            onError?(status)
        }
        refreshMaskedState()
    }

    private func refreshMaskedState() {
        guard let session else { return }
        var state = secure_keypad_masked_state_t(length: 0, display_state: 0)
        let status = secure_keypad_session_refresh(session, &state)
        guard status == 0 else {
            onError?(status)
            return
        }
        let count = Int(state.length)
        displayLabel.text = protectedPresentation ? "Protected" : String(repeating: "•", count: count)
        displayLabel.accessibilityLabel = secureKeypadAccessibilityLabel(
            length: count,
            protected: protectedPresentation
        )
        onMaskedStateChanged?(state.length, state.display_state)
    }

    private func installProtectionObservers() {
        let center = NotificationCenter.default
        notificationTokens.append(center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.refreshProtectionState()
        })
        notificationTokens.append(center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            self?.refreshProtectionState()
        })
        notificationTokens.append(center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.refreshProtectionState()
        })
        refreshProtectionState()
    }

    private func refreshProtectionState() {
        let applicationIsActive = UIApplication.shared.applicationState == .active
        let screenIsCaptured = window?.windowScene?.screen.isCaptured ?? false
        setProtectedPresentation(secureKeypadShouldProtectPresentation(
            applicationIsActive: applicationIsActive,
            screenIsCaptured: screenIsCaptured
        ))
    }

    private func setProtectedPresentation(_ protected: Bool) {
        protectedPresentation = protected
        isUserInteractionEnabled = !protected
        refreshMaskedState()
    }

    private func validate(layout: SecureKeypadLayout) throws {
        guard !layout.rows.isEmpty else { throw SecureKeypadViewError.invalidLayout }
        var ids = Set<String>()
        for row in layout.rows {
            guard !row.isEmpty else { throw SecureKeypadViewError.invalidLayout }
            for key in row {
                guard (1...64).contains(key.id.utf8.count), ids.insert(key.id).inserted,
                      key.id.unicodeScalars.allSatisfy({ $0.value < 128 }), key.label.utf8.count <= 16 else {
                    throw SecureKeypadViewError.invalidLayout
                }
            }
        }
    }
}

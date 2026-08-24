import Foundation
import AudioToolbox
import UIKit

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
    public let testId: String?

    public init(
        id: String,
        label: String,
        role: SecureKeyRole,
        accessibilityLabel: String? = nil,
        testId: String? = nil
    ) {
        self.id = id
        self.label = label
        self.role = role
        self.accessibilityLabel = accessibilityLabel ?? label
        self.testId = testId
    }
}

public enum SecureKeypadLayoutDirection {
    case ltr
    case rtl
}

public struct SecureKeypadSlots {
    public var header: Bool
    public var display: Bool
    public var footer: Bool
    public var error: Bool

    public init(header: Bool = true, display: Bool = true, footer: Bool = true, error: Bool = true) {
        self.header = header
        self.display = display
        self.footer = footer
        self.error = error
    }
}

public enum SecureKeypadHapticFeedback {
    case none
    case light
    case medium
    case heavy
}

public enum SecureKeypadSoundFeedback {
    case none
    case click
}

/// A row-based presentation layout with public IDs only.
public struct SecureKeypadLayout {
    public let rows: [[SecureKeySpec]]
    public let direction: SecureKeypadLayoutDirection
    public let randomizeInputKeys: Bool
    public let slots: SecureKeypadSlots

    public init(
        rows: [[SecureKeySpec]],
        direction: SecureKeypadLayoutDirection = .ltr,
        randomizeInputKeys: Bool = false,
        slots: SecureKeypadSlots = SecureKeypadSlots()
    ) {
        self.rows = rows
        self.direction = direction
        self.randomizeInputKeys = randomizeInputKeys
        self.slots = slots
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
    public var pressDuration: TimeInterval = 0.08
    public var maskRevealDuration: TimeInterval = 0
    public var hapticFeedback: SecureKeypadHapticFeedback = .light
    public var soundFeedback: SecureKeypadSoundFeedback = .none

    public init() {}
}

private enum SecureKeypadInputPolicy {
    case numeric
    case ascii
    case hangul
}

private struct RetainedConfiguration {
    let layout: SecureKeypadLayout
    let theme: SecureKeypadTheme
    let maxTokens: Int
    let timeoutMs: UInt64
    let policy: SecureKeypadInputPolicy
}

private let hangulInputKeyIds: Set<String> = [
    "jamo-giyeok", "jamo-ssang-giyeok", "jamo-nieun", "jamo-digeut", "jamo-ssang-digeut",
    "jamo-rieul", "jamo-mieum", "jamo-bieub", "jamo-ssang-bieub", "jamo-siot", "jamo-ssang-siot",
    "jamo-ieung", "jamo-jieut", "jamo-ssang-jieut", "jamo-chieut", "jamo-kieuk", "jamo-tieut",
    "jamo-pieup", "jamo-hieuh", "vowel-a", "vowel-ae", "vowel-ya", "vowel-yae", "vowel-eo",
    "vowel-e", "vowel-yeo", "vowel-ye", "vowel-o", "vowel-wa", "vowel-wae", "vowel-oe", "vowel-yo",
    "vowel-u", "vowel-wo", "vowel-we", "vowel-wi", "vowel-yu", "vowel-eu", "vowel-ui", "vowel-i",
    "tail-giyeok", "tail-ssang-giyeok", "tail-giyeok-siot", "tail-nieun", "tail-nieun-jieut",
    "tail-nieun-hieuh", "tail-digeut", "tail-rieul", "tail-rieul-giyeok", "tail-rieul-mieum",
    "tail-rieul-bieub", "tail-rieul-siot", "tail-rieul-tieut", "tail-rieul-pieup", "tail-rieul-hieuh",
    "tail-mieum", "tail-bieub", "tail-bieub-siot", "tail-siot", "tail-ssang-siot", "tail-ieung",
    "tail-jieut", "tail-chieut", "tail-kieuk", "tail-tieut", "tail-pieup", "tail-hieuh",
]

/// Native-owned opaque submission. It cannot be serialized to JavaScript.
public final class SecureKeypadSubmission {
    fileprivate var raw: OpaquePointer?

    fileprivate init(raw: OpaquePointer) {
        self.raw = raw
    }

    fileprivate var isConsumed: Bool {
        raw == nil
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
    /// The consumer receives the originating native view so an application can
    /// bind authentication state to one keypad instance instead of a global
    /// mutable account context.
    public typealias Consumer = (SecureKeypadView, SecureKeypadSubmission) -> Bool

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

    static func deliver(_ submission: SecureKeypadSubmission, from view: SecureKeypadView) -> Bool {
        lock.lock()
        let current = consumer
        lock.unlock()
        guard let current else { return false }
        return current(view, submission) && submission.isConsumed
    }
}

/// Non-secret native renderer errors.
public enum SecureKeypadViewError: Error {
    case invalidLayout
    case abiMismatch
    case nativeFailure(UInt32)
}

/// Secure Native iOS keypad.
///
/// The view never creates an editable text control. Key IDs are sent to the Rust C ABI,
/// and only masked length/state are rendered. The submission callback remains
/// native-only and must not be bridged to JavaScript or Dart.
public class SecureKeypadView: UIView {
    private var session: OpaquePointer?
    private var retainedConfiguration: RetainedConfiguration?
    internal var hasActiveSession: Bool { session != nil }
    internal var onSessionNeedsReconfiguration: (() -> Void)? = nil
    private let displayLabel = UILabel()
    private let keypadStack = UIStackView()
    private let rootContainer = UIStackView()
    private var theme = SecureKeypadTheme()
    private var protectedPresentation = false
    private var notificationTokens: [NSObjectProtocol] = []
    private var contentPaddingConstraints: [NSLayoutConstraint] = []
    private var lastCancelRequest: Int64?
    private var lastHeadlessKeyPress: Int64?
    private var activeLayout: [String: SecureKeySpec] = [:]
    private var headlessHostMode = false

    /// Called with a native-only submission that the host must close or authenticate natively.
    public var onSubmit: ((SecureKeypadSubmission) -> Void)?

    /// Called with a public, non-secret native error code.
    public var onError: ((UInt32) -> Void)?

    /// Called with masked length and non-secret display state only.
    public var onMaskedStateChanged: ((UInt32, UInt32) -> Void)?

    /// Detaches framework callbacks so adapter teardown cannot retain this view.
    public func clearBridgeCallbacks() {
        onSubmit = nil
        onError = nil
        onMaskedStateChanged = nil
        onSessionNeedsReconfiguration = nil
    }

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
        if window == nil {
            releaseNativeSessionPreservingConfiguration()
        }
        refreshProtectionState()
        requestSessionReconfigurationIfNeeded()
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

    /// Selects the renderer mode. Headless host mode hides native controls and
    /// accepts only explicitly acknowledged public key-ID commands.
    public func setRendererMode(mode: String, acknowledgeLowerAssurance: Bool) {
        guard (mode == "secure-native" && !acknowledgeLowerAssurance) ||
                (mode == "headless-host" && acknowledgeLowerAssurance) else {
            onError?(1)
            return
        }
        headlessHostMode = mode == "headless-host"
        rootContainer.isHidden = headlessHostMode
        accessibilityElementsHidden = headlessHostMode
    }

    /// Delivers one monotonic public key-ID command in acknowledged headless mode.
    public func requestHeadlessKeyPress(requestId: Int64, keyId: String) {
        guard session != nil,
              headlessHostMode,
              secureKeypadShouldAcceptProgrammaticKeyPress(protected: protectedPresentation),
              requestId >= 0,
              keyId.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil else {
            onError?(1)
            return
        }
        if let previous = lastHeadlessKeyPress, requestId < previous {
            onError?(1)
            return
        }
        if lastHeadlessKeyPress == requestId { return }
        guard let key = activeLayout[keyId] else {
            onError?(1)
            return
        }
        if activate(key: key) {
            lastHeadlessKeyPress = requestId
        }
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
        try validate(layout: layout, policy: policy)
        try validate(theme: theme)
        guard secure_keypad_abi_version() == 2 else {
            throw SecureKeypadViewError.abiMismatch
        }

        retainedConfiguration = nil
        releaseNativeSessionPreservingConfiguration()
        let configuration = RetainedConfiguration(
            layout: layout,
            theme: theme,
            maxTokens: maxTokens,
            timeoutMs: timeoutMs,
            policy: policy
        )
        try startSession(configuration: configuration)
        guard session != nil else {
            throw SecureKeypadViewError.nativeFailure(secureKeypadInternalError)
        }
        retainedConfiguration = configuration
    }

    private func startSession(configuration: RetainedConfiguration) throws {
        guard secure_keypad_abi_version() == 2 else {
            throw SecureKeypadViewError.abiMismatch
        }
        var newSession: OpaquePointer?
        let status: UInt32
        switch configuration.policy {
        case .numeric:
            status = secure_keypad_session_new_numeric(
                UInt32(configuration.maxTokens),
                configuration.timeoutMs,
                &newSession
            )
        case .ascii:
            status = secure_keypad_session_new_ascii(
                UInt32(configuration.maxTokens),
                configuration.timeoutMs,
                &newSession
            )
        case .hangul:
            status = secure_keypad_session_new_hangul(
                UInt32(configuration.maxTokens),
                configuration.timeoutMs,
                &newSession
            )
        }
        guard status == 0, let newSession else {
            throw SecureKeypadViewError.nativeFailure(status)
        }
        session = newSession
        activeLayout = Dictionary(uniqueKeysWithValues: configuration.layout.rows.flatMap { $0 }.map { ($0.id, $0) })
        self.theme = configuration.theme
        rootContainer.spacing = configuration.theme.keyGap
        keypadStack.spacing = configuration.theme.keyGap
        if contentPaddingConstraints.count == 4 {
            contentPaddingConstraints[0].constant = configuration.theme.contentPadding
            contentPaddingConstraints[1].constant = -configuration.theme.contentPadding
            contentPaddingConstraints[2].constant = configuration.theme.contentPadding
            contentPaddingConstraints[3].constant = -configuration.theme.contentPadding
        }
        displayLabel.font = .systemFont(ofSize: configuration.theme.keyFontSize, weight: configuration.theme.keyFontWeight)
        render(layout: configuration.layout)
        refreshMaskedState()
    }

    /// Releases the native session and zeroizes pending input.
    public func releaseSession() {
        releaseNativeSessionPreservingConfiguration()
        retainedConfiguration = nil
    }

    private func releaseNativeSessionPreservingConfiguration() {
        if let session {
            secure_keypad_session_free(session)
            self.session = nil
        }
        displayLabel.text = protectedPresentation ? "Protected" : ""
        displayLabel.accessibilityLabel = secureKeypadAccessibilityLabel(length: 0, protected: protectedPresentation)
    }

    /// Cancels the native session and zeroizes any pending input.
    public func cancelSession() {
        _ = cancelSessionAndReport()
    }

    private func cancelSessionAndReport() -> Bool {
        guard let session else { return false }
        let status = secure_keypad_session_cancel(session)
        if status != 0 {
            releaseNativeSessionPreservingConfiguration()
            onError?(status)
            return false
        }
        refreshMaskedState()
        return true
    }

    /// Applies a monotonic, non-secret host command exactly once.
    public func requestCancel(_ requestId: Int64) {
        switch secureKeypadMonotonicCommandDecision(previous: lastCancelRequest, requestId: requestId) {
        case .invalid:
            onError?(1)
        case .ignore:
            return
        case .accept:
            if cancelSessionAndReport() {
                lastCancelRequest = requestId
            }
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
        let semanticDirection: UISemanticContentAttribute = layout.direction == .rtl
            ? .forceRightToLeft
            : .forceLeftToRight
        rootContainer.semanticContentAttribute = semanticDirection
        keypadStack.semanticContentAttribute = semanticDirection
        displayLabel.isHidden = !layout.slots.display
        for row in presentationRows(layout.rows, randomizeInputKeys: layout.randomizeInputKeys) {
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
                    UIView.animate(withDuration: buttonTheme.pressDuration) {
                        button.transform = button.isHighlighted
                            ? CGAffineTransform(scaleX: 0.98, y: 0.98)
                            : .identity
                    }
                }
                button.accessibilityLabel = key.accessibilityLabel
                button.accessibilityIdentifier = key.testId ?? key.id
                button.addAction(UIAction { [weak self] _ in
                    self?.activate(key: key)
                }, for: .touchUpInside)
                rowStack.addArrangedSubview(button)
            }
            rowStack.heightAnchor.constraint(equalToConstant: theme.keyHeight).isActive = true
            keypadStack.addArrangedSubview(rowStack)
        }
    }

    /// Reorders only input-role keys; action keys retain their configured positions.
    private func presentationRows(
        _ rows: [[SecureKeySpec]],
        randomizeInputKeys: Bool
    ) -> [[SecureKeySpec]] {
        var generator = SystemRandomNumberGenerator()
        return secureKeypadPresentationRows(
            rows,
            randomizeInputKeys: randomizeInputKeys,
            isInput: { $0.role == .input },
            using: &generator
        )
    }

    @discardableResult
    private func activate(key: SecureKeySpec) -> Bool {
        guard let session else { return false }
        guard secureKeypadShouldAcceptProgrammaticKeyPress(protected: protectedPresentation) else { return false }
        performFeedback()
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
            return false
        }
        if status != 0 {
            onError?(status)
            return false
        }
        refreshMaskedState()
        return true
    }

    private func refreshMaskedState() {
        guard let session else { return }
        var state = secure_keypad_masked_state_t(length: 0, display_state: 0)
        let status = secure_keypad_session_refresh(session, &state)
        guard status == 0 else {
            releaseSession()
            onError?(status)
            return
        }
        let count = Int(state.length)
        guard secureKeypadIsValidRenderedLength(count) else {
            releaseSession()
            onError?(secureKeypadInternalError)
            return
        }
        guard secureKeypadIsValidDisplayState(state.display_state) else {
            releaseSession()
            onError?(secureKeypadInternalError)
            return
        }
        let maskedText = secureKeypadMaskedDisplayText(length: count, protected: protectedPresentation)
        if theme.maskRevealDuration == 0 {
            displayLabel.text = maskedText
        } else {
            UIView.transition(
                with: displayLabel,
                duration: theme.maskRevealDuration,
                options: [.transitionCrossDissolve, .beginFromCurrentState, .allowAnimatedContent]
            ) {
                self.displayLabel.text = maskedText
            }
        }
        displayLabel.accessibilityLabel = secureKeypadAccessibilityLabel(length: count, protected: protectedPresentation)
        onMaskedStateChanged?(state.length, state.display_state)
    }

    private func performFeedback() {
        switch theme.hapticFeedback {
        case .none:
            break
        case .light:
            UIImpactFeedbackGenerator(style: .light).impactOccurred()
        case .medium:
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        case .heavy:
            UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
        }
        if theme.soundFeedback == .click {
            AudioServicesPlaySystemSound(1104)
        }
    }

    private func installProtectionObservers() {
        let center = NotificationCenter.default
        notificationTokens.append(center.addObserver(forName: UIScene.willDeactivateNotification, object: nil, queue: .main) { [weak self] note in
            guard let self, self.isCurrentSceneNotification(note.object) else { return }
            self.handleWillResignActive()
        })
        notificationTokens.append(center.addObserver(forName: UIScene.didActivateNotification, object: nil, queue: .main) { [weak self] note in
            guard let self, self.isCurrentSceneNotification(note.object) else { return }
            self.refreshProtectionState()
            self.requestSessionReconfigurationIfNeeded()
        })
        notificationTokens.append(center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            self?.handleScreenCaptureChange()
        })
        refreshProtectionState()
    }

    private func isCurrentSceneNotification(_ object: Any?) -> Bool {
        guard let notificationScene = object as? UIWindowScene,
              let currentScene = window?.windowScene else { return false }
        return notificationScene === currentScene
    }

    private func requestSessionReconfigurationIfNeeded() {
        guard secureKeypadShouldReconfigureSession(
            hasWindow: window != nil,
            sessionIsNil: session == nil,
            protected: protectedPresentation
        ) else { return }
        if let onSessionNeedsReconfiguration {
            onSessionNeedsReconfiguration()
        } else {
            reconfigureRetainedConfiguration()
        }
    }

    private func reconfigureRetainedConfiguration() {
        guard let configuration = retainedConfiguration, session == nil else { return }
        do {
            try startSession(configuration: configuration)
            if session == nil {
                retainedConfiguration = nil
            }
        } catch let error as SecureKeypadViewError {
            retainedConfiguration = nil
            releaseNativeSessionPreservingConfiguration()
            switch error {
            case .nativeFailure(let status):
                onError?(status)
            case .invalidLayout, .abiMismatch:
                onError?(secureKeypadInternalError)
            }
        } catch {
            retainedConfiguration = nil
            releaseNativeSessionPreservingConfiguration()
            onError?(secureKeypadInternalError)
        }
    }

    private func handleWillResignActive() {
        releaseNativeSessionPreservingConfiguration()
        setProtectedPresentation(true)
        onMaskedStateChanged?(0, 3)
    }

    private func handleScreenCaptureChange() {
        let screenIsCaptured = window?.windowScene?.screen.isCaptured ?? false
        if secureKeypadShouldClearSessionForScreenCapture(
            screenIsCaptured: screenIsCaptured,
            sessionIsLive: session != nil
        ) {
            releaseNativeSessionPreservingConfiguration()
            onMaskedStateChanged?(0, 3)
        }
        refreshProtectionState()
        requestSessionReconfigurationIfNeeded()
    }

    private func refreshProtectionState() {
        let applicationIsActive = window?.windowScene?.activationState == .foregroundActive
        let screenIsCaptured = window?.windowScene?.screen.isCaptured ?? false
        setProtectedPresentation(secureKeypadShouldProtectPresentation(
            applicationIsActive: applicationIsActive,
            screenIsCaptured: screenIsCaptured
        ))
    }

    private func setProtectedPresentation(_ protected: Bool) {
        protectedPresentation = protected
        isUserInteractionEnabled = !protected
        if protected, session != nil {
            releaseNativeSessionPreservingConfiguration()
            onMaskedStateChanged?(0, 3)
        }
        guard session != nil else {
            displayLabel.text = protected ? "Protected" : ""
            displayLabel.accessibilityLabel = secureKeypadAccessibilityLabel(length: 0, protected: protected)
            return
        }
        refreshMaskedState()
    }

    private func validate(layout: SecureKeypadLayout, policy: SecureKeypadInputPolicy) throws {
        guard (1...16).contains(layout.rows.count) else { throw SecureKeypadViewError.invalidLayout }
        var ids = Set<String>()
        var totalKeys = 0
        for row in layout.rows {
            guard (1...32).contains(row.count) else { throw SecureKeypadViewError.invalidLayout }
            totalKeys += row.count
            guard totalKeys <= 512 else { throw SecureKeypadViewError.invalidLayout }
            for key in row {
                guard (1...64).contains(key.id.utf8.count), ids.insert(key.id).inserted,
                      key.id.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil,
                      key.testId == nil || key.testId?.range(of: "^[a-z0-9][a-z0-9._-]{0,63}$", options: .regularExpression) != nil,
                      key.id.unicodeScalars.allSatisfy({ $0.value < 128 }), key.label.utf8.count <= 16,
                      key.accessibilityLabel.utf8.count <= 80 else {
                    throw SecureKeypadViewError.invalidLayout
                }
                switch key.role {
                case .input:
                    guard isCanonicalInputKeyId(key.id, policy) else {
                        throw SecureKeypadViewError.invalidLayout
                    }
                default:
                    break
                }
            }
        }
    }

    private func isCanonicalInputKeyId(_ keyId: String, _ policy: SecureKeypadInputPolicy) -> Bool {
        switch policy {
        case .numeric:
            return keyId.range(of: "^digit-[0-9]$", options: .regularExpression) != nil
        case .ascii:
            guard keyId.range(of: "^ascii-[0-9a-f]{2}$", options: .regularExpression) != nil,
                  let codePoint = UInt8(keyId.dropFirst("ascii-".count), radix: 16) else {
                return false
            }
            return (0x20...0x7e).contains(codePoint)
        case .hangul:
            return hangulInputKeyIds.contains(keyId)
        }
    }

    private func validate(theme: SecureKeypadTheme) throws {
        guard theme.keyHeight.isFinite, theme.keyHeight >= 32, theme.keyHeight <= 160,
              theme.keyGap.isFinite, theme.keyGap >= 0, theme.keyGap <= 48,
              theme.keyRadius.isFinite, theme.keyRadius >= 0, theme.keyRadius <= 80,
              theme.contentPadding.isFinite, theme.contentPadding >= 0, theme.contentPadding <= 80,
              theme.keyFontSize.isFinite, theme.keyFontSize >= 10, theme.keyFontSize <= 72,
              supportedFontWeight(theme.keyFontWeight),
              theme.pressDuration.isFinite, theme.pressDuration >= 0, theme.pressDuration <= 0.5,
              theme.maskRevealDuration.isFinite, theme.maskRevealDuration >= 0,
              theme.maskRevealDuration <= 2 else {
            throw SecureKeypadViewError.invalidLayout
        }
    }

    private func supportedFontWeight(_ value: UIFont.Weight) -> Bool {
        [UIFont.Weight.regular, .medium, .semibold, .bold].contains { supported in
            abs(supported.rawValue - value.rawValue) < 0.0001
        }
    }
}

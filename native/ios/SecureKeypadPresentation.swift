import Foundation

let secureKeypadMaxRenderedLength = 4_096
let secureKeypadInternalError: UInt32 = 7

/// Returns whether the native presentation must hide sensitive UI state.
/// Screen capture remains protected across app-active transitions.
func secureKeypadShouldProtectPresentation(applicationIsActive: Bool, screenIsCaptured: Bool) -> Bool {
    !applicationIsActive || screenIsCaptured
}

/// Returns whether a native masked length is safe to render.
func secureKeypadIsValidRenderedLength(_ length: Int) -> Bool {
    (0...secureKeypadMaxRenderedLength).contains(length)
}

/// Produces masked display text from length only.
func secureKeypadMaskedDisplayText(length: Int, protected: Bool) -> String {
    precondition(secureKeypadIsValidRenderedLength(length))
    return protected ? "Protected" : String(repeating: "•", count: length)
}

/// Produces accessibility text from masked state only.
func secureKeypadAccessibilityLabel(length: Int, protected: Bool) -> String {
    precondition(secureKeypadIsValidRenderedLength(length))
    if protected {
        return "Protected"
    }
    return length == 0 ? "No input" : "\(length) characters entered"
}

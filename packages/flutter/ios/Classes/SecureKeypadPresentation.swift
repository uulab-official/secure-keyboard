import Foundation

/// Returns whether the native presentation must hide sensitive UI state.
/// Screen capture remains protected across app-active transitions.
func secureKeypadShouldProtectPresentation(applicationIsActive: Bool, screenIsCaptured: Bool) -> Bool {
    !applicationIsActive || screenIsCaptured
}

/// Produces accessibility text from masked state only.
func secureKeypadAccessibilityLabel(length: Int, protected: Bool) -> String {
    if protected {
        return "Protected"
    }
    return length == 0 ? "No input" : "\(length) characters entered"
}

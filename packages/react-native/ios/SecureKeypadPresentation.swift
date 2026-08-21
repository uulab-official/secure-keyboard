import Foundation

let secureKeypadMaxRenderedLength = 4_096
let secureKeypadInternalError: UInt32 = 7

enum SecureKeypadCommandDecision: Equatable {
    case accept
    case ignore
    case invalid
}

func secureKeypadMonotonicCommandDecision(previous: Int64?, requestId: Int64) -> SecureKeypadCommandDecision {
    if requestId < 0 {
        return .invalid
    }
    if let previous, requestId < previous { return .invalid }
    if let previous, requestId == previous {
        return .ignore
    }
    return .accept
}

/// Returns whether the native presentation must hide sensitive UI state.
/// Screen capture remains protected across app-active transitions.
func secureKeypadShouldProtectPresentation(applicationIsActive: Bool, screenIsCaptured: Bool) -> Bool {
    !applicationIsActive || screenIsCaptured
}

/// Returns whether a native masked length is safe to render.
func secureKeypadIsValidRenderedLength(_ length: Int) -> Bool {
    (0...secureKeypadMaxRenderedLength).contains(length)
}

/// Returns whether a native display-state code is part of the public contract.
func secureKeypadIsValidDisplayState(_ value: UInt32) -> Bool {
    (0...3).contains(value)
}

/// Converts a native display-state code without normalizing invalid values.
func secureKeypadDisplayStateName(_ value: UInt32) -> String {
    switch value {
    case 0: return "empty"
    case 1: return "masked"
    case 2: return "submitted"
    case 3: return "cancelled"
    default: return "invalid"
    }
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

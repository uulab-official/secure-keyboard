import Foundation

/// Produces accessibility text from masked state only.
func secureKeypadAccessibilityLabel(length: Int, protected: Bool) -> String {
    if protected {
        return "Protected"
    }
    return length == 0 ? "No input" : "\(length) characters entered"
}

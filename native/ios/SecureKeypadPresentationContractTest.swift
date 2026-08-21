import Foundation

@main
struct SecureKeypadPresentationContractTest {
    static func main() {
        precondition(!secureKeypadShouldProtectPresentation(applicationIsActive: true, screenIsCaptured: false))
        precondition(secureKeypadShouldProtectPresentation(applicationIsActive: false, screenIsCaptured: false))
        precondition(secureKeypadShouldProtectPresentation(applicationIsActive: true, screenIsCaptured: true))
        precondition(secureKeypadMaskedDisplayText(length: 0, protected: false) == "")
        precondition(secureKeypadMaskedDisplayText(length: 3, protected: false) == "•••")
        precondition(secureKeypadMaskedDisplayText(length: 3, protected: true) == "Protected")
        precondition(secureKeypadAccessibilityLabel(length: 0, protected: false) == "No input")
        precondition(secureKeypadAccessibilityLabel(length: 3, protected: false) == "3 characters entered")
        precondition(secureKeypadAccessibilityLabel(length: 3, protected: true) == "Protected")
        precondition(!secureKeypadIsValidRenderedLength(-1))
        precondition(!secureKeypadIsValidRenderedLength(4_097))
        precondition(secureKeypadIsValidDisplayState(0))
        precondition(secureKeypadIsValidDisplayState(3))
        precondition(!secureKeypadIsValidDisplayState(4))
        precondition(secureKeypadDisplayStateName(0) == "empty")
        precondition(secureKeypadDisplayStateName(3) == "cancelled")
        precondition(secureKeypadDisplayStateName(4) == "invalid")
    }
}

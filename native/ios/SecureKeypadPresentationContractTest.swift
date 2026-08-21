import Foundation

@main
struct SecureKeypadPresentationContractTest {
    static func main() {
        precondition(!secureKeypadShouldProtectPresentation(applicationIsActive: true, screenIsCaptured: false))
        precondition(secureKeypadShouldProtectPresentation(applicationIsActive: false, screenIsCaptured: false))
        precondition(secureKeypadShouldProtectPresentation(applicationIsActive: true, screenIsCaptured: true))
        precondition(secureKeypadAccessibilityLabel(length: 0, protected: false) == "No input")
        precondition(secureKeypadAccessibilityLabel(length: 3, protected: false) == "3 characters entered")
        precondition(secureKeypadAccessibilityLabel(length: 3, protected: true) == "Protected")
    }
}

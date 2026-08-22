import Foundation

private struct ContractRandomGenerator: RandomNumberGenerator {
    private var state: UInt64 = 0x9e3779b97f4a7c15

    mutating func next() -> UInt64 {
        state = state &* 6_364_136_223_846_793_005 &+ 1
        return state
    }
}

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
        let activeSnapshot = [
            "displayState=masked",
            "maskedDisplay=•••",
            "accessibility=3 characters entered",
            "protected=false",
        ].joined(separator: "\n")
        precondition(secureKeypadSecuritySnapshot(
            length: 3,
            protected: false,
            displayState: 1
        ) == activeSnapshot)
        let protectedSnapshot = [
            "displayState=masked",
            "maskedDisplay=Protected",
            "accessibility=Protected",
            "protected=true",
        ].joined(separator: "\n")
        precondition(secureKeypadSecuritySnapshot(
            length: 3,
            protected: true,
            displayState: 1
        ) == protectedSnapshot)
        precondition(secureKeypadSecuritySnapshot(length: 3, protected: false, displayState: 4) == nil)
        precondition(secureKeypadMonotonicCommandDecision(previous: nil, requestId: 0) == .accept)
        precondition(secureKeypadMonotonicCommandDecision(previous: 4, requestId: 5) == .accept)
        precondition(secureKeypadMonotonicCommandDecision(previous: 4, requestId: 4) == .ignore)
        precondition(secureKeypadMonotonicCommandDecision(previous: 4, requestId: 3) == .invalid)

        let rows = [
            [(id: "digit-1", input: true), (id: "backspace", input: false), (id: "digit-2", input: true)],
            [(id: "digit-3", input: true), (id: "submit", input: false), (id: "digit-4", input: true)],
        ]
        var generator = ContractRandomGenerator()
        let randomized = secureKeypadPresentationRows(
            rows,
            randomizeInputKeys: true,
            isInput: { $0.input },
            using: &generator
        )
        precondition(randomized.map(\.count) == rows.map(\.count))
        precondition(randomized[0][1].id == "backspace")
        precondition(randomized[1][1].id == "submit")
        precondition(Set(randomized.flatMap { $0 }.filter { $0.input }.map(\.id)) == Set([
            "digit-1", "digit-2", "digit-3", "digit-4",
        ]))
        let unchanged = secureKeypadPresentationRows(
            rows,
            randomizeInputKeys: false,
            isInput: { $0.input },
            using: &generator
        )
        precondition(unchanged.map { $0.map(\.id) } == rows.map { $0.map(\.id) })
    }
}

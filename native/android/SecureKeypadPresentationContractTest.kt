package com.uulab.securekeypad

/** Standalone accessibility/masking contract test; no Android runtime is required. */
fun main() {
    check(secureKeypadMaskedDisplayText(0) == "")
    check(secureKeypadMaskedDisplayText(3) == "•••")
    check(secureKeypadAccessibilityLabel(0) == "No input")
    check(secureKeypadAccessibilityLabel(3) == "3 characters entered")
    check(secureKeypadMaskedDisplayText(3, protected = true) == "Protected")
    check(secureKeypadAccessibilityLabel(3, protected = true) == "Protected")
    check(runCatching { secureKeypadMaskedDisplayText(-1) }.isFailure)
    check(runCatching { secureKeypadAccessibilityLabel(4_097) }.isFailure)
    check(secureKeypadIsValidDisplayState(0))
    check(secureKeypadIsValidDisplayState(3))
    check(!secureKeypadIsValidDisplayState(4))
    check(secureKeypadDisplayStateName(0) == "empty")
    check(secureKeypadDisplayStateName(3) == "cancelled")
    check(secureKeypadDisplayStateName(4) == "invalid")
    val activeSnapshot = listOf(
        "displayState=masked",
        "maskedDisplay=•••",
        "accessibility=3 characters entered",
        "protected=false",
    ).joinToString("\n")
    check(secureKeypadSecuritySnapshot(length = 3, protected = false, displayState = 1) == activeSnapshot)
    val protectedSnapshot = listOf(
        "displayState=masked",
        "maskedDisplay=Protected",
        "accessibility=Protected",
        "protected=true",
    ).joinToString("\n")
    check(secureKeypadSecuritySnapshot(length = 3, protected = true, displayState = 1) == protectedSnapshot)
    check(runCatching {
        secureKeypadSecuritySnapshot(length = 3, protected = false, displayState = 4)
    }.isFailure)
    check(secureKeypadDecodeMaskedState(Long.MIN_VALUE) == null)
    check(secureKeypadDecodeMaskedState((3L shl 32) or 1L) == (3 to 1))
    check(secureKeypadMonotonicCommandDecision(null, 0) == SecureKeypadCommandDecision.ACCEPT)
    check(secureKeypadMonotonicCommandDecision(4, 5) == SecureKeypadCommandDecision.ACCEPT)
    check(secureKeypadMonotonicCommandDecision(4, 4) == SecureKeypadCommandDecision.IGNORE)
    check(secureKeypadMonotonicCommandDecision(4, 3) == SecureKeypadCommandDecision.INVALID)
}

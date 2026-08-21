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
}

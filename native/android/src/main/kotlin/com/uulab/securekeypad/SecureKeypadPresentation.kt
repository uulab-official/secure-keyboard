package com.uulab.securekeypad

internal const val SECURE_KEYPAD_MAX_RENDERED_LENGTH = 4_096
internal const val SECURE_KEYPAD_ERROR_INTERNAL = 7

/** Returns whether a native display-state code is part of the public contract. */
internal fun secureKeypadIsValidDisplayState(value: Int): Boolean = value in 0..3

/** Returns masked presentation text without ever accepting a user-supplied value. */
internal fun secureKeypadMaskedDisplayText(length: Int, protected: Boolean = false): String {
    require(length in 0..SECURE_KEYPAD_MAX_RENDERED_LENGTH)
    return if (protected) "Protected" else "•".repeat(length)
}

/** Returns an accessibility announcement containing only state and length. */
internal fun secureKeypadAccessibilityLabel(length: Int, protected: Boolean = false): String {
    require(length in 0..SECURE_KEYPAD_MAX_RENDERED_LENGTH)
    if (protected) return "Protected"
    return if (length == 0) "No input" else "$length characters entered"
}

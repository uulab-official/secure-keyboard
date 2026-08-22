package com.uulab.securekeypad

internal const val SECURE_KEYPAD_MAX_RENDERED_LENGTH = 4_096
internal const val SECURE_KEYPAD_ERROR_INTERNAL = 7
internal const val SECURE_KEYPAD_ERROR_INVALID = 1
internal const val SECURE_KEYPAD_NATIVE_REFRESH_ERROR = Long.MIN_VALUE

internal enum class SecureKeypadCommandDecision {
    ACCEPT,
    IGNORE,
    INVALID,
}

internal fun secureKeypadMonotonicCommandDecision(previous: Long?, requestId: Long): SecureKeypadCommandDecision {
    if (requestId < 0 || (previous != null && requestId < previous)) {
        return SecureKeypadCommandDecision.INVALID
    }
    if (previous != null && requestId == previous) {
        return SecureKeypadCommandDecision.IGNORE
    }
    return SecureKeypadCommandDecision.ACCEPT
}

/** Returns whether a native display-state code is part of the public contract. */
internal fun secureKeypadIsValidDisplayState(value: Int): Boolean = value in 0..3

/** Decodes the packed JNI state while keeping native failure distinct from empty state. */
internal fun secureKeypadDecodeMaskedState(packed: Long): Pair<Int, Int>? {
    if (packed == SECURE_KEYPAD_NATIVE_REFRESH_ERROR) return null
    return (packed ushr 32).toInt() to packed.toInt()
}

/** Converts a native display-state code without normalizing invalid values. */
internal fun secureKeypadDisplayStateName(value: Int): String = when (value) {
    0 -> "empty"
    1 -> "masked"
    2 -> "submitted"
    3 -> "cancelled"
    else -> "invalid"
}

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

/** Returns a deterministic security-facing presentation snapshot. */
internal fun secureKeypadSecuritySnapshot(length: Int, protected: Boolean = false, displayState: Int): String? {
    if (length !in 0..SECURE_KEYPAD_MAX_RENDERED_LENGTH || !secureKeypadIsValidDisplayState(displayState)) {
        return null
    }
    return listOf(
        "displayState=${secureKeypadDisplayStateName(displayState)}",
        "maskedDisplay=${secureKeypadMaskedDisplayText(length, protected)}",
        "accessibility=${secureKeypadAccessibilityLabel(length, protected)}",
        "protected=$protected",
    ).joinToString("\n")
}

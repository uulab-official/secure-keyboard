package com.uulab.securekeypad

private fun validConfiguration(): MutableMap<String, Any?> = mutableMapOf(
    "layout" to mapOf(
        "schemaVersion" to 1,
        "rows" to listOf(
            listOf(mapOf("id" to "digit-1", "label" to "1", "role" to "input")),
            listOf(mapOf("id" to "submit", "label" to "Continue", "role" to "submit")),
        ),
    ),
    "theme" to mapOf(
        "schemaVersion" to 1,
        "colors" to mapOf(
            "background" to "#101114",
            "keyBackground" to "#23262D",
            "keyForeground" to "#FFFFFF",
            "keyPressedBackground" to "#3B82F6",
            "keyDisabledBackground" to "#4B5563",
            "error" to "#F87171",
        ),
        "metrics" to mapOf(
            "keyHeight" to 56,
            "keyGap" to 8,
            "keyRadius" to 12,
            "contentPadding" to 16,
        ),
        "typography" to mapOf("keyFontSize" to 24, "keyFontWeight" to "600"),
    ),
    "inputPolicy" to "numeric",
    "maxTokens" to 8,
    "timeoutMs" to 60_000,
)

fun main() {
    val parsed = SecureKeypadBridgeConfigParser.parse(validConfiguration())
    check(parsed.layout.rows.size == 2)
    check(parsed.maxTokens == 8)

    val topLevelSecret = validConfiguration().also { it["password"] = "never accepted" }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(topLevelSecret) }.isFailure)

    val nestedSecret = validConfiguration()
    @Suppress("UNCHECKED_CAST")
    val layout = (nestedSecret.getValue("layout") as Map<String, Any?>).toMutableMap()
    layout["secret"] = "never accepted"
    nestedSecret["layout"] = layout
    check(runCatching { SecureKeypadBridgeConfigParser.parse(nestedSecret) }.isFailure)

    val fractionalMaxTokens = validConfiguration().also { it["maxTokens"] = 1.5 }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(fractionalMaxTokens) }.isFailure)

    val fractionalTimeout = validConfiguration().also { it["timeoutMs"] = 1.5 }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(fractionalTimeout) }.isFailure)

    val booleanMaxTokens = validConfiguration().also { it["maxTokens"] = true }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(booleanMaxTokens) }.isFailure)
}

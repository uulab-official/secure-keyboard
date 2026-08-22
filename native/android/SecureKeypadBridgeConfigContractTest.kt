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
    val configuration = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val layout = (it.getValue("layout") as Map<String, Any?>).toMutableMap()
        layout["direction"] = "rtl"
        layout["slots"] = mapOf("header" to false, "display" to false, "footer" to true, "error" to false)
        layout["rows"] = listOf(
            listOf(
                mapOf(
                    "id" to "digit-1",
                    "label" to "1",
                    "role" to "input",
                    "testId" to "pin.one",
                ),
            ),
            listOf(mapOf("id" to "submit", "label" to "Continue", "role" to "submit")),
        )
        it["layout"] = layout
    }
    val parsed = SecureKeypadBridgeConfigParser.parse(configuration)
    check(parsed.layout.rows.size == 2)
    check(parsed.layout.direction == SecureKeypadLayoutDirection.RTL)
    check(!parsed.layout.slots.display)
    check(parsed.layout.rows[0][0].testId == "pin.one")
    check(runCatching {
        SecureKeypadBridgeConfigParser.parse(validConfiguration().also {
            @Suppress("UNCHECKED_CAST")
            val layout = (it.getValue("layout") as Map<String, Any?>).toMutableMap()
            layout["direction"] = true
            it["layout"] = layout
        })
    }.isFailure)
    check(parsed.maxTokens == 8)
    check(parsed.mode == "secure-native")
    check(!parsed.acknowledgeLowerAssurance)

    val headless = validConfiguration().also {
        it["mode"] = "headless-host"
        it["acknowledgeLowerAssurance"] = true
        it["headlessKeyPress"] = mapOf("token" to 0, "keyId" to "digit-1")
    }
    check(SecureKeypadBridgeConfigParser.parse(headless).mode == "headless-host")
    check(SecureKeypadBridgeConfigParser.parse(headless).headlessKeyPress?.keyId == "digit-1")
    check(runCatching {
        SecureKeypadBridgeConfigParser.parse(validConfiguration().also { it["mode"] = "headless-host" })
    }.isFailure)
    check(runCatching {
        SecureKeypadBridgeConfigParser.parse(validConfiguration().also { it["acknowledgeLowerAssurance"] = true })
    }.isFailure)
    check(runCatching {
        SecureKeypadBridgeConfigParser.parse(validConfiguration().also {
            it["headlessKeyPress"] = mapOf("token" to 0, "keyId" to "digit-1")
        })
    }.isFailure)
    check(runCatching {
        SecureKeypadBridgeConfigParser.parse(validConfiguration().also {
            it["headlessKeyPress"] = "invalid"
        })
    }.isFailure)

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

    val secretInSlots = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val layout = (it.getValue("layout") as Map<String, Any?>).toMutableMap()
        layout["slots"] = mapOf("secret" to true)
        it["layout"] = layout
    }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(secretInSlots) }.isFailure)

    val secretInAnimation = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val theme = (it.getValue("theme") as Map<String, Any?>).toMutableMap()
        theme["animation"] = mapOf("rawInput" to "never accepted")
        it["theme"] = theme
    }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(secretInAnimation) }.isFailure)

    val invalidErrorColor = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val theme = (it.getValue("theme") as Map<String, Any?>).toMutableMap()
        theme["colors"] = mapOf(
            "background" to "#101114",
            "keyBackground" to "#23262D",
            "keyForeground" to "#FFFFFF",
            "keyPressedBackground" to "#3B82F6",
            "keyDisabledBackground" to "#4B5563",
            "error" to "never accepted",
        )
        it["theme"] = theme
    }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(invalidErrorColor) }.isFailure)

    val missingDisabledColor = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val theme = (it.getValue("theme") as Map<String, Any?>).toMutableMap()
        @Suppress("UNCHECKED_CAST")
        val colors = (theme.getValue("colors") as Map<String, Any?>).toMutableMap()
        colors.remove("keyDisabledBackground")
        theme["colors"] = colors
        it["theme"] = theme
    }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(missingDisabledColor) }.isFailure)

    val invalidDisabledColor = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val theme = (it.getValue("theme") as Map<String, Any?>).toMutableMap()
        @Suppress("UNCHECKED_CAST")
        val colors = (theme.getValue("colors") as Map<String, Any?>).toMutableMap()
        colors["keyDisabledBackground"] = "not-a-color"
        theme["colors"] = colors
        it["theme"] = theme
    }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(invalidDisabledColor) }.isFailure)

    val signedColor = validConfiguration().also {
        @Suppress("UNCHECKED_CAST")
        val theme = (it.getValue("theme") as Map<String, Any?>).toMutableMap()
        @Suppress("UNCHECKED_CAST")
        val colors = (theme.getValue("colors") as Map<String, Any?>).toMutableMap()
        colors["background"] = "#+12345"
        theme["colors"] = colors
        it["theme"] = theme
    }
    check(runCatching { SecureKeypadBridgeConfigParser.parse(signedColor) }.isFailure)
}

package com.uulab.securekeypad

import kotlin.math.floor

/** Public framework configuration decoded before it reaches the native view. */
internal data class SecureKeypadBridgeConfiguration(
    val layout: SecureKeypadLayout,
    val theme: SecureKeypadTheme,
    val inputPolicy: String,
    val maxTokens: Int,
    val timeoutMs: Long,
    val mode: String,
    val acknowledgeLowerAssurance: Boolean,
    val headlessKeyPress: SecureKeypadHeadlessKeyPress?,
)

internal data class SecureKeypadHeadlessKeyPress(val token: Long, val keyId: String)

internal object SecureKeypadBridgeConfigParser {
    fun parse(value: Map<*, *>): SecureKeypadBridgeConfiguration {
        requireKeys(
            value,
            "layout",
            "theme",
            "inputPolicy",
            "maxTokens",
            "timeoutMs",
            "mode",
            "acknowledgeLowerAssurance",
            "headlessKeyPress",
        )
        val layout = parseLayout(value["layout"] as? Map<*, *> ?: invalid())
        val theme = parseTheme(value["theme"] as? Map<*, *> ?: invalid())
        val inputPolicy = (value["inputPolicy"] as? String) ?: "numeric"
        require(inputPolicy == "numeric" || inputPolicy == "ascii" || inputPolicy == "hangul")
        val maxTokens = integer(value["maxTokens"], 8L)
        val timeoutMs = integer(value["timeoutMs"], 60_000L)
        require(maxTokens in 1L..4_096L)
        require(timeoutMs in 1L..86_400_000L)
        val mode = (value["mode"] as? String) ?: "secure-native"
        require(mode == "secure-native" || mode == "headless-host")
        val acknowledgeLowerAssurance = value["acknowledgeLowerAssurance"]?.let { it as? Boolean ?: invalid() } ?: false
        require(
            (mode == "secure-native" && !acknowledgeLowerAssurance) ||
                (mode == "headless-host" && acknowledgeLowerAssurance),
        )
        val headlessKeyPress = if (!value.containsKey("headlessKeyPress") || value["headlessKeyPress"] == null) {
            null
        } else {
            val command = value["headlessKeyPress"] as? Map<*, *> ?: invalid()
            requireKeys(command, "token", "keyId")
            val token = integer(command["token"] ?: invalid(), 0L)
            require(token in 0L..9_007_199_254_740_991L)
            val keyId = command["keyId"] as? String ?: invalid()
            require(keyId.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}")))
            SecureKeypadHeadlessKeyPress(token, keyId)
        }
        require(headlessKeyPress == null || mode == "headless-host")
        return SecureKeypadBridgeConfiguration(
            layout,
            theme,
            inputPolicy,
            maxTokens.toInt(),
            timeoutMs,
            mode,
            acknowledgeLowerAssurance,
            headlessKeyPress,
        )
    }

    private fun parseLayout(value: Map<*, *>): SecureKeypadLayout {
        requireKeys(value, "schemaVersion", "id", "locale", "direction", "rows", "slots")
        require((value["schemaVersion"] as? Number)?.toDouble() == 1.0)
        if (value.containsKey("id")) {
            val id = value["id"] as? String ?: invalid()
            require(id.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}")))
        }
        if (value.containsKey("locale")) {
            val locale = value["locale"] as? String ?: invalid()
            require(locale.matches(Regex("[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})?")))
        }
        if (value.containsKey("direction")) {
            require(value["direction"] == "ltr" || value["direction"] == "rtl")
        }
        optionalMap(value["slots"], "header", "display", "footer", "error")?.values?.forEach {
            require(it is Boolean)
        }
        val rows = value["rows"] as? List<*> ?: invalid()
        require(rows.isNotEmpty() && rows.size <= 16)
        val ids = HashSet<String>()
        val parsedRows = rows.map { rowValue ->
            val row = rowValue as? List<*> ?: invalid()
            require(row.isNotEmpty() && row.size <= 32)
            row.map { keyValue ->
                val key = keyValue as? Map<*, *> ?: invalid()
                requireKeys(key, "id", "label", "icon", "role", "accessibilityLabel", "testId")
                val id = key["id"] as? String ?: invalid()
                require(id.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}")))
                require(ids.add(id))
                if (key.containsKey("label")) require(key["label"] is String)
                if (key.containsKey("icon")) {
                    val icon = key["icon"] as? String ?: invalid()
                    require(icon.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}")))
                }
                if (key.containsKey("accessibilityLabel")) require(key["accessibilityLabel"] is String)
                if (key.containsKey("testId")) {
                    val testId = key["testId"] as? String ?: invalid()
                    require(testId.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}")))
                }
                val roleValue = key["role"] as? String ?: invalid()
                val role = when (roleValue) {
                    "input" -> SecureKeyRole.INPUT
                    "backspace" -> SecureKeyRole.BACKSPACE
                    "clear" -> SecureKeyRole.CLEAR
                    "submit" -> SecureKeyRole.SUBMIT
                    "cancel" -> SecureKeyRole.CANCEL
                    "spacer" -> SecureKeyRole.SPACER
                    else -> invalid()
                }
                val label = (key["label"] as? String) ?: (key["icon"] as? String) ?: id
                require(label.toByteArray(Charsets.UTF_8).size <= 16)
                val accessibilityLabel = (key["accessibilityLabel"] as? String) ?: label
                require(accessibilityLabel.toByteArray(Charsets.UTF_8).size <= 80)
                SecureKeySpec(id, label, role, accessibilityLabel)
            }
        }
        return SecureKeypadLayout(parsedRows)
    }

    private fun parseTheme(value: Map<*, *>): SecureKeypadTheme {
        requireKeys(value, "schemaVersion", "colors", "metrics", "typography", "animation", "feedback")
        require((value["schemaVersion"] as? Number)?.toDouble() == 1.0)
        val colors = value["colors"] as? Map<*, *> ?: invalid()
        val metrics = value["metrics"] as? Map<*, *> ?: invalid()
        requireExactKeys(colors, "background", "keyBackground", "keyForeground", "keyPressedBackground", "keyDisabledBackground", "error")
        requireExactKeys(metrics, "keyHeight", "keyGap", "keyRadius", "contentPadding")
        val typography = optionalMap(value["typography"], "keyFontSize", "keyFontWeight") ?: invalid()
        val keyHeight = metric(metrics, "keyHeight", 32f, 160f)
        val keyGap = metric(metrics, "keyGap", 0f, 48f)
        val keyRadius = metric(metrics, "keyRadius", 0f, 80f)
        val contentPadding = metric(metrics, "contentPadding", 0f, 80f)
        color(colors, "error")
        val keyFontSize = number(typography["keyFontSize"] ?: invalid(), 10f, 72f)
        validateFontWeight(typography["keyFontWeight"] ?: invalid())
        optionalMap(value["animation"], "pressDurationMs", "maskRevealDurationMs")?.let {
            if (it.containsKey("pressDurationMs")) boundedInteger(it["pressDurationMs"], 0L, 500L)
            if (it.containsKey("maskRevealDurationMs")) boundedInteger(it["maskRevealDurationMs"], 0L, 2_000L)
        }
        optionalMap(value["feedback"], "haptic", "sound")?.let {
            if (it.containsKey("haptic")) {
                val haptic = it["haptic"] as? String ?: invalid()
                require(haptic in setOf("none", "light", "medium", "heavy"))
            }
            if (it.containsKey("sound")) {
                val sound = it["sound"] as? String ?: invalid()
                require(sound in setOf("none", "click"))
            }
        }
        return SecureKeypadTheme(
            backgroundColor = color(colors, "background"),
            keyColor = color(colors, "keyBackground"),
            keyPressedColor = color(colors, "keyPressedBackground"),
            keyTextColor = color(colors, "keyForeground"),
            keyHeightPx = keyHeight.toInt(),
            keyGapPx = keyGap.toInt(),
            keyRadiusPx = keyRadius,
            keyFontSizePx = keyFontSize,
            contentPaddingPx = contentPadding.toInt(),
        ).also {
            require(contentPadding >= 0f)
        }
    }

    private fun color(value: Map<*, *>, key: String): Int {
        val text = value[key] as? String ?: invalid()
        require(text.startsWith("#"))
        val hex = text.removePrefix("#")
        require(hex.length == 6 || hex.length == 8)
        val raw = hex.toLongOrNull(16) ?: invalid()
        return if (hex.length == 6) {
            (raw or 0xff00_0000L).toInt()
        } else {
            raw.toInt()
        }
    }

    private fun metric(value: Map<*, *>, key: String, minimum: Float, maximum: Float): Float =
        number(value[key] ?: invalid(), minimum, maximum)

    private fun number(value: Any, minimum: Float, maximum: Float): Float {
        val result = (value as? Number)?.toFloat() ?: invalid()
        require(result.isFinite() && result in minimum..maximum)
        return result
    }

    private fun integer(value: Any?, default: Long): Long {
        if (value == null) return default
        val result = (value as? Number)?.toDouble() ?: invalid()
        require(result.isFinite() && floor(result) == result)
        return result.toLong()
    }

    private fun boundedInteger(value: Any?, minimum: Long, maximum: Long): Long {
        val result = (value as? Number)?.toDouble() ?: invalid()
        require(result.isFinite() && floor(result) == result && result >= minimum && result <= maximum)
        return result.toLong()
    }

    private fun validateFontWeight(value: Any) {
        when (value) {
            is String -> require(value == "400" || value == "500" || value == "600" || value == "700")
            is Number -> require(boundedInteger(value, 400L, 700L) in setOf(400L, 500L, 600L, 700L))
            else -> invalid()
        }
    }

    private fun optionalMap(value: Any?, vararg allowed: String): Map<*, *>? {
        if (value == null) return null
        val map = value as? Map<*, *> ?: invalid()
        requireKeys(map, *allowed)
        return map
    }

    private fun requireKeys(value: Map<*, *>, vararg allowed: String) {
        val allowedKeys = allowed.toSet()
        require(value.keys.all { it is String && it in allowedKeys })
    }

    private fun requireExactKeys(value: Map<*, *>, vararg required: String) {
        val requiredKeys = required.toSet()
        require(value.size == requiredKeys.size)
        require(value.keys.all { it is String && it in requiredKeys })
    }

    private fun invalid(): Nothing = throw IllegalArgumentException("invalid secure keypad configuration")
}

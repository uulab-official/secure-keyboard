package com.uulab.securekeypad

import kotlin.math.floor

/** Public framework configuration decoded before it reaches the native view. */
internal data class SecureKeypadBridgeConfiguration(
    val layout: SecureKeypadLayout,
    val theme: SecureKeypadTheme,
    val inputPolicy: String,
    val maxTokens: Int,
    val timeoutMs: Long,
)

internal object SecureKeypadBridgeConfigParser {
    fun parse(value: Map<*, *>): SecureKeypadBridgeConfiguration {
        requireKeys(value, "layout", "theme", "inputPolicy", "maxTokens", "timeoutMs")
        val layout = parseLayout(value["layout"] as? Map<*, *> ?: invalid())
        val theme = parseTheme(value["theme"] as? Map<*, *> ?: invalid())
        val inputPolicy = (value["inputPolicy"] as? String) ?: "numeric"
        require(inputPolicy == "numeric" || inputPolicy == "ascii" || inputPolicy == "hangul")
        val maxTokens = integer(value["maxTokens"], 8L)
        val timeoutMs = integer(value["timeoutMs"], 60_000L)
        require(maxTokens in 1L..4_096L)
        require(timeoutMs in 1L..86_400_000L)
        return SecureKeypadBridgeConfiguration(layout, theme, inputPolicy, maxTokens.toInt(), timeoutMs)
    }

    private fun parseLayout(value: Map<*, *>): SecureKeypadLayout {
        requireKeys(value, "schemaVersion", "id", "locale", "direction", "rows", "slots")
        require((value["schemaVersion"] as? Number)?.toDouble() == 1.0)
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
                require(label.length <= 16)
                val accessibilityLabel = (key["accessibilityLabel"] as? String) ?: label
                require(accessibilityLabel.length <= 80)
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
        requireKeys(colors, "background", "keyBackground", "keyForeground", "keyPressedBackground", "keyDisabledBackground", "error")
        requireKeys(metrics, "keyHeight", "keyGap", "keyRadius", "contentPadding")
        val typography = value["typography"] as? Map<*, *>
        typography?.let { requireKeys(it, "keyFontSize", "keyFontWeight") }
        val keyHeight = metric(metrics, "keyHeight", 1f, 256f)
        val keyGap = metric(metrics, "keyGap", 0f, 256f)
        val keyRadius = metric(metrics, "keyRadius", 0f, 256f)
        val contentPadding = metric(metrics, "contentPadding", 0f, 256f)
        val keyFontSize = typography?.get("keyFontSize")?.let { number(it, 1f, 128f) } ?: 24f
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

    private fun requireKeys(value: Map<*, *>, vararg allowed: String) {
        val allowedKeys = allowed.toSet()
        require(value.keys.all { it is String && it in allowedKeys })
    }

    private fun invalid(): Nothing = throw IllegalArgumentException("invalid secure keypad configuration")
}

package com.uulab.securekeypad.flutter

import android.content.Context
import android.view.View
import com.uulab.securekeypad.SecureKeypadBridgeConfigParser
import com.uulab.securekeypad.SecureKeypadNativeSubmissionRouter
import com.uulab.securekeypad.SecureKeypadView
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.StandardMessageCodec
import io.flutter.plugin.platform.PlatformView
import io.flutter.plugin.platform.PlatformViewFactory
import java.util.ArrayDeque
import kotlin.math.floor

/** Flutter registration for the native-only keypad PlatformView. */
public class SecureKeypadFlutterPlugin : FlutterPlugin {
    private var viewType: String = VIEW_TYPE

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        binding.platformViewRegistry.registerViewFactory(
            viewType,
            SecureKeypadFlutterViewFactory(binding.binaryMessenger),
        )
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) = Unit

    private companion object {
        const val VIEW_TYPE = "secure_keypad/native"
    }
}

private class SecureKeypadFlutterViewFactory(
    private val messenger: BinaryMessenger,
) : PlatformViewFactory(StandardMessageCodec.INSTANCE) {
    override fun create(context: Context, viewId: Int, args: Any?): PlatformView =
        SecureKeypadFlutterPlatformView(context, viewId, args, messenger)
}

private class SecureKeypadFlutterPlatformView(
    context: Context,
    viewId: Int,
    args: Any?,
    messenger: BinaryMessenger,
) : PlatformView, EventChannel.StreamHandler {
    private val keypad = SecureKeypadView(context)
    private val eventChannel = EventChannel(messenger, "secure_keypad/events/$viewId")
    private val controlChannel = MethodChannel(messenger, "secure_keypad/control/$viewId")
    private var eventSink: EventChannel.EventSink? = null
    private val pendingEvents = ArrayDeque<Map<String, Any?>>()
    private var activeConfiguration: com.uulab.securekeypad.SecureKeypadBridgeConfiguration? = null

    init {
        eventChannel.setStreamHandler(this)
        controlChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                "cancel" -> {
                    keypad.cancelSession()
                    result.success(null)
                }
                "pressKey" -> requestHeadlessKeyPress(call.arguments, result)
                else -> result.notImplemented()
            }
        }
        keypad.onSessionNeedsReconfiguration = {
            activeConfiguration?.let { applyConfiguration(it, replayHeadlessKeyPress = false) }
        }
        keypad.onMaskedStateChanged = { length, displayState ->
            emit(
                mapOf(
                    "type" to "state",
                    "length" to length,
                    "displayState" to com.uulab.securekeypad.secureKeypadDisplayStateName(displayState),
                ),
            )
            if (displayState == 3) emit(mapOf("type" to "result", "code" to "cancelled"))
        }
        keypad.onError = {
            emit(mapOf("type" to "result", "code" to "error"))
        }
        keypad.onSubmit = { submission ->
            if (SecureKeypadNativeSubmissionRouter.deliver(submission, keypad)) {
                emit(mapOf("type" to "result", "code" to "success"))
            } else {
                submission.close()
                emit(mapOf("type" to "result", "code" to "error"))
            }
        }
        val configuration = try {
            SecureKeypadBridgeConfigParser.parse(args as? Map<*, *> ?: invalid())
        } catch (_: IllegalArgumentException) {
            emit(mapOf("type" to "result", "code" to "invalid"))
            null
        }
        if (configuration != null) {
            activeConfiguration = configuration
            applyConfiguration(configuration, replayHeadlessKeyPress = true)
        }
    }

    override fun getView(): View = keypad

    override fun dispose() {
        eventChannel.setStreamHandler(null)
        controlChannel.setMethodCallHandler(null)
        keypad.onSessionNeedsReconfiguration = null
        keypad.clearBridgeCallbacks()
        keypad.releaseSession()
        eventSink = null
        pendingEvents.clear()
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        eventSink = events
        while (pendingEvents.isNotEmpty()) {
            events.success(pendingEvents.removeFirst())
        }
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    private fun emit(event: Map<String, Any?>) {
        val sink = eventSink
        if (sink != null) {
            sink.success(event)
            return
        }
        if (event["type"] == "state" && pendingEvents.peekLast()?.get("type") == "state") {
            pendingEvents.removeLast()
        }
        if (pendingEvents.size >= MAX_PENDING_EVENTS) {
            val iterator = pendingEvents.iterator()
            var removedState = false
            while (iterator.hasNext()) {
                if (iterator.next()["type"] == "state") {
                    iterator.remove()
                    removedState = true
                    break
                }
            }
            if (!removedState) pendingEvents.removeFirst()
        }
        pendingEvents.addLast(event)
    }

    private fun invalid(): Nothing = throw IllegalArgumentException("invalid secure keypad configuration")

    private fun requestHeadlessKeyPress(arguments: Any?, result: MethodChannel.Result) {
        val command = arguments as? Map<*, *> ?: return result.error("invalid", null, null)
        if (command.size != 2 || command.keys.any { it !is String || it !in HEADLESS_KEY_PRESS_KEYS }) {
            return result.error("invalid", null, null)
        }
        val rawToken = command["token"] as? Number ?: return result.error("invalid", null, null)
        val tokenValue = rawToken.toDouble()
        if (!tokenValue.isFinite() || tokenValue < 0.0 ||
            tokenValue > MAX_HEADLESS_KEY_PRESS_TOKEN.toDouble() || tokenValue != floor(tokenValue)
        ) {
            return result.error("invalid", null, null)
        }
        val keyId = command["keyId"] as? String ?: return result.error("invalid", null, null)
        if (!keyId.matches(HEADLESS_KEY_ID_PATTERN)) {
            return result.error("invalid", null, null)
        }
        keypad.requestHeadlessKeyPress(tokenValue.toLong(), keyId)
        result.success(null)
    }

    private fun applyConfiguration(
        configuration: com.uulab.securekeypad.SecureKeypadBridgeConfiguration,
        replayHeadlessKeyPress: Boolean,
    ) {
        try {
            keypad.setRendererMode(configuration.mode, configuration.acknowledgeLowerAssurance)
            if (configuration.inputPolicy == "hangul") {
                keypad.configureHangul(
                    configuration.layout,
                    configuration.theme,
                    configuration.maxTokens,
                    configuration.timeoutMs,
                )
            } else if (configuration.inputPolicy == "ascii") {
                keypad.configureAscii(
                    configuration.layout,
                    configuration.theme,
                    configuration.maxTokens,
                    configuration.timeoutMs,
                )
            } else {
                keypad.configureNumeric(
                    configuration.layout,
                    configuration.theme,
                    configuration.maxTokens,
                    configuration.timeoutMs,
                )
            }
            if (replayHeadlessKeyPress) {
                configuration.headlessKeyPress?.let { keypad.requestHeadlessKeyPress(it.token, it.keyId) }
            }
        } catch (_: IllegalArgumentException) {
            emit(mapOf("type" to "result", "code" to "error"))
        }
    }

    private companion object {
        const val MAX_PENDING_EVENTS = 32
        const val MAX_HEADLESS_KEY_PRESS_TOKEN = 9_007_199_254_740_991L
        val HEADLESS_KEY_ID_PATTERN = Regex("[a-z0-9][a-z0-9._-]{0,63}")
        val HEADLESS_KEY_PRESS_KEYS = setOf("token", "keyId")
    }
}

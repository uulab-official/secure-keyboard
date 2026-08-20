package com.uulab.securekeypad.flutter

import android.content.Context
import android.view.View
import com.uulab.securekeypad.SecureKeypadBridgeConfigParser
import com.uulab.securekeypad.SecureKeypadView
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.StandardMessageCodec
import io.flutter.plugin.platform.PlatformView
import io.flutter.plugin.platform.PlatformViewFactory

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
    private var eventSink: EventChannel.EventSink? = null

    init {
        eventChannel.setStreamHandler(this)
        keypad.onMaskedStateChanged = { length, displayState ->
            eventSink?.success(
                mapOf(
                    "type" to "state",
                    "length" to length,
                    "displayState" to com.uulab.securekeypad.secureKeypadDisplayStateName(displayState),
                ),
            )
        }
        keypad.onError = {
            eventSink?.success(mapOf("type" to "result", "code" to "error"))
        }
        keypad.onSubmit = { submission ->
            submission.close()
            eventSink?.success(mapOf("type" to "result", "code" to "success"))
        }
        try {
            val configuration = SecureKeypadBridgeConfigParser.parse(args as? Map<*, *> ?: invalid())
            if (configuration.inputPolicy == "hangul") {
                keypad.configureHangul(
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
        } catch (_: IllegalArgumentException) {
            eventSink?.success(mapOf("type" to "result", "code" to "invalid"))
        }
    }

    override fun getView(): View = keypad

    override fun dispose() {
        eventChannel.setStreamHandler(null)
        keypad.releaseSession()
        eventSink = null
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    private fun invalid(): Nothing = throw IllegalArgumentException("invalid secure keypad configuration")
}

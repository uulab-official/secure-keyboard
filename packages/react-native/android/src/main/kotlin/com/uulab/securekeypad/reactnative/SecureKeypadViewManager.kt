package com.uulab.securekeypad.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType
import com.facebook.react.bridge.ReactContext
import com.facebook.react.bridge.WritableMap
import com.facebook.react.uimanager.SimpleViewManager
import com.facebook.react.uimanager.ThemedReactContext
import com.facebook.react.uimanager.annotations.ReactProp
import com.facebook.react.uimanager.events.RCTEventEmitter
import com.facebook.react.module.annotations.ReactModule
import com.uulab.securekeypad.SecureKeypadBridgeConfigParser
import com.uulab.securekeypad.SecureKeypadNativeSubmissionRouter
import com.uulab.securekeypad.SecureKeypadView
import java.util.WeakHashMap

/** React Native manager that transports public configuration and masked events only. */
@ReactModule(name = SecureKeypadViewManager.NAME)
public class SecureKeypadViewManager : SimpleViewManager<SecureKeypadView>() {
    private val pendingConfigurations = WeakHashMap<SecureKeypadView, MutableMap<String, Any?>>()

    override fun getName(): String = NAME

    override fun createViewInstance(reactContext: ThemedReactContext): SecureKeypadView {
        return SecureKeypadView(reactContext).also { view ->
            view.onMaskedStateChanged = { length, displayState ->
                emitState(view, length, displayState)
                if (displayState == 3) emitResult(view, "cancelled")
            }
            view.onError = { code ->
                emitResult(view, if (code == 4) "locked" else "error")
            }
            view.onSubmit = { submission ->
                if (SecureKeypadNativeSubmissionRouter.deliver(submission)) {
                    emitResult(view, "success")
                } else {
                    submission.close()
                    emitResult(view, "error")
                }
            }
        }
    }

    @ReactProp(name = "layout")
    public fun setLayout(view: SecureKeypadView, value: ReadableMap?) {
        setConfigurationValue(view, "layout", value?.toPublicMap())
    }

    @ReactProp(name = "theme")
    public fun setTheme(view: SecureKeypadView, value: ReadableMap?) {
        setConfigurationValue(view, "theme", value?.toPublicMap())
    }

    @ReactProp(name = "inputPolicy", defaultString = "numeric")
    public fun setInputPolicy(view: SecureKeypadView, value: String?) {
        setConfigurationValue(view, "inputPolicy", value ?: "numeric")
    }

    @ReactProp(name = "maxTokens", defaultInt = 8)
    public fun setMaxTokens(view: SecureKeypadView, value: Int) {
        setConfigurationValue(view, "maxTokens", value)
    }

    @ReactProp(name = "timeoutMs", defaultInt = 60_000)
    public fun setTimeoutMs(view: SecureKeypadView, value: Int) {
        setConfigurationValue(view, "timeoutMs", value)
    }

    override fun onDropViewInstance(view: SecureKeypadView) {
        pendingConfigurations.remove(view)
        view.releaseSession()
        super.onDropViewInstance(view)
    }

    override fun getExportedCustomDirectEventTypeConstants(): MutableMap<String, Any> = mutableMapOf(
        "topMaskedStateChange" to mutableMapOf("registrationName" to "onMaskedStateChange"),
        "topResult" to mutableMapOf("registrationName" to "onResult"),
    )

    private fun setConfigurationValue(view: SecureKeypadView, key: String, value: Any?) {
        val configuration = pendingConfigurations.getOrPut(view) { mutableMapOf() }
        configuration[key] = value
        val layout = configuration["layout"] as? Map<*, *>
        val theme = configuration["theme"] as? Map<*, *>
        if (layout == null || theme == null) return
        try {
            val parsed = SecureKeypadBridgeConfigParser.parse(configuration)
            if (parsed.inputPolicy == "hangul") {
                view.configureHangul(parsed.layout, parsed.theme, parsed.maxTokens, parsed.timeoutMs)
            } else {
                view.configureNumeric(parsed.layout, parsed.theme, parsed.maxTokens, parsed.timeoutMs)
            }
        } catch (_: IllegalArgumentException) {
            view.releaseSession()
            emitResult(view, "invalid")
        }
    }

    private fun emitState(view: SecureKeypadView, length: Int, displayState: Int) {
        val payload = Arguments.createMap().apply {
            putInt("length", length)
            putString("displayState", com.uulab.securekeypad.secureKeypadDisplayStateName(displayState))
        }
        emit(view, "topMaskedStateChange", payload)
    }

    private fun emitResult(view: SecureKeypadView, code: String) {
        val payload = Arguments.createMap().apply {
            putString("type", "result")
            putString("code", code)
        }
        emit(view, "topResult", payload)
    }

    private fun emit(view: SecureKeypadView, eventName: String, payload: WritableMap) {
        val context = view.context as? ReactContext ?: return
        if (view.id == NO_ID) return
        context.getJSModule(RCTEventEmitter::class.java).receiveEvent(view.id, eventName, payload)
    }

    private companion object {
        const val NAME = "SecureKeypadView"
        const val NO_ID = -1
    }
}

private fun ReadableMap.toPublicMap(): Map<String, Any?> {
    val result = mutableMapOf<String, Any?>()
    val iterator = keySetIterator()
    while (iterator.hasNextKey()) {
        val key = iterator.nextKey()
        result[key] = getPublicValue(key)
    }
    return result
}

private fun ReadableArray.toPublicList(): List<Any?> = (0 until size()).map { index ->
    when (getType(index)) {
        ReadableType.Map -> getMap(index)?.toPublicMap()
        ReadableType.Array -> getArray(index)?.toPublicList()
        ReadableType.String -> getString(index)
        ReadableType.Number -> getDouble(index)
        ReadableType.Boolean -> getBoolean(index)
        ReadableType.Null -> null
    }
}

private fun ReadableMap.getPublicValue(key: String): Any? = when (getType(key)) {
    ReadableType.Map -> getMap(key)?.toPublicMap()
    ReadableType.Array -> getArray(key)?.toPublicList()
    ReadableType.String -> getString(key)
    ReadableType.Number -> getDouble(key)
    ReadableType.Boolean -> getBoolean(key)
    ReadableType.Null -> null
}

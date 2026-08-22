package com.uulab.securekeypad.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType
import com.facebook.react.bridge.ReactContext
import com.facebook.react.bridge.WritableMap
import com.facebook.react.uimanager.SimpleViewManager
import com.facebook.react.uimanager.ThemedReactContext
import com.facebook.react.uimanager.UIManagerHelper
import com.facebook.react.uimanager.annotations.ReactProp
import com.facebook.react.uimanager.events.Event
import com.facebook.react.uimanager.events.EventDispatcher
import com.facebook.react.module.annotations.ReactModule
import com.uulab.securekeypad.SecureKeypadBridgeConfigParser
import com.uulab.securekeypad.SecureKeypadNativeSubmissionRouter
import com.uulab.securekeypad.SecureKeypadView
import kotlin.math.floor
import java.lang.ref.WeakReference
import java.util.WeakHashMap

/** React Native manager that transports public configuration and masked events only. */
@ReactModule(name = SecureKeypadViewManager.NAME)
public class SecureKeypadViewManager : SimpleViewManager<SecureKeypadView>() {
    private val pendingConfigurations = WeakHashMap<SecureKeypadView, MutableMap<String, Any?>>()
    private val configuredViews = WeakHashMap<SecureKeypadView, Boolean>()

    override fun getName(): String = NAME

    override fun createViewInstance(reactContext: ThemedReactContext): SecureKeypadView {
        return SecureKeypadView(reactContext).also { view ->
            val weakView = WeakReference(view)
            view.onSessionNeedsReconfiguration = {
                val currentView = weakView.get()
                val layout = currentView?.let { pendingConfigurations[it]?.get("layout") }
                if (currentView != null && layout != null) {
                    setConfigurationValue(currentView, "layout", layout)
                }
            }
            view.onMaskedStateChanged = { length, displayState ->
                emitState(view, length, displayState)
                if (displayState == 3) emitResult(view, "cancelled")
            }
            view.onError = { code ->
                emitResult(view, if (code == 4) "locked" else "error")
            }
            view.onSubmit = { submission ->
                if (SecureKeypadNativeSubmissionRouter.deliver(submission, view)) {
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
        setConfigurationValue(view, "layout") { value?.toPublicMap(LAYOUT_KEYS) }
    }

    @ReactProp(name = "theme")
    public fun setTheme(view: SecureKeypadView, value: ReadableMap?) {
        setConfigurationValue(view, "theme") { value?.toPublicMap(THEME_KEYS) }
    }

    @ReactProp(name = "inputPolicy")
    public fun setInputPolicy(view: SecureKeypadView, value: String?) {
        setConfigurationValue(view, "inputPolicy", value ?: "numeric")
    }

    @ReactProp(name = "mode")
    public fun setMode(view: SecureKeypadView, value: String?) {
        setConfigurationValue(view, "mode", value ?: "secure-native")
    }

    @ReactProp(name = "acknowledgeLowerAssurance", defaultBoolean = false)
    public fun setAcknowledgeLowerAssurance(view: SecureKeypadView, value: Boolean) {
        setConfigurationValue(view, "acknowledgeLowerAssurance", value)
    }

    @ReactProp(name = "maxTokens", defaultInt = 8)
    public fun setMaxTokens(view: SecureKeypadView, value: Int) {
        setConfigurationValue(view, "maxTokens", value)
    }

    @ReactProp(name = "timeoutMs", defaultInt = 60_000)
    public fun setTimeoutMs(view: SecureKeypadView, value: Int) {
        setConfigurationValue(view, "timeoutMs", value)
    }

    @ReactProp(name = "cancelRequest", defaultDouble = 0.0)
    public fun setCancelRequest(view: SecureKeypadView, value: Double) {
        if (!value.isFinite() || value < 0.0 || value > 9_007_199_254_740_991.0 || floor(value) != value) {
            emitResult(view, "invalid")
            return
        }
        view.requestCancel(value.toLong())
    }

    @ReactProp(name = "headlessKeyPress")
    public fun setHeadlessKeyPress(view: SecureKeypadView, value: ReadableMap?) {
        setConfigurationValue(view, "headlessKeyPress") { value?.toPublicMap(HEADLESS_KEY_PRESS_KEYS) }
    }

    override fun onDropViewInstance(view: SecureKeypadView) {
        pendingConfigurations.remove(view)
        configuredViews.remove(view)
        view.onSessionNeedsReconfiguration = null
        view.clearBridgeCallbacks()
        view.releaseSession()
        super.onDropViewInstance(view)
    }

    override fun getExportedCustomDirectEventTypeConstants(): MutableMap<String, Any> = mutableMapOf(
        "topMaskedStateChange" to mutableMapOf("registrationName" to "onMaskedStateChange"),
        "topResult" to mutableMapOf("registrationName" to "onResult"),
    )

    private fun setConfigurationValue(view: SecureKeypadView, key: String, value: Any?) {
        setConfigurationValue(view, key) { value }
    }

    private fun setConfigurationValue(view: SecureKeypadView, key: String, valueProvider: () -> Any?) {
        val value = try {
            valueProvider()
        } catch (_: IllegalArgumentException) {
            pendingConfigurations.remove(view)
            view.releaseSession()
            emitResult(view, "invalid")
            return
        }
        val configuration = pendingConfigurations.getOrPut(view) { mutableMapOf() }
        configuration[key] = value
        val layout = configuration["layout"] as? Map<*, *>
        val theme = configuration["theme"] as? Map<*, *>
        if (layout == null || theme == null) {
            if (configuredViews.remove(view) != null) {
                pendingConfigurations.remove(view)
                view.releaseSession()
            }
            return
        }
        try {
            val parsed = SecureKeypadBridgeConfigParser.parse(configuration)
            view.setRendererMode(parsed.mode, parsed.acknowledgeLowerAssurance)
            if (parsed.inputPolicy == "hangul") {
                view.configureHangul(parsed.layout, parsed.theme, parsed.maxTokens, parsed.timeoutMs)
            } else if (parsed.inputPolicy == "ascii") {
                view.configureAscii(parsed.layout, parsed.theme, parsed.maxTokens, parsed.timeoutMs)
            } else {
                view.configureNumeric(parsed.layout, parsed.theme, parsed.maxTokens, parsed.timeoutMs)
            }
            configuredViews[view] = true
            parsed.headlessKeyPress?.let { view.requestHeadlessKeyPress(it.token, it.keyId) }
        } catch (_: IllegalArgumentException) {
            pendingConfigurations.remove(view)
            configuredViews.remove(view)
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
        val dispatcher: EventDispatcher = UIManagerHelper.getEventDispatcher(context) ?: return
        dispatcher.dispatchEvent(SecureKeypadEvent(UIManagerHelper.getSurfaceId(view), view.id, eventName, payload))
    }

    private companion object {
        const val NAME = "SecureKeypadView"
        const val NO_ID = -1
    }
}

private class SecureKeypadEvent(
    surfaceId: Int,
    viewTag: Int,
    private val name: String,
    private val data: WritableMap,
) : Event<SecureKeypadEvent>(surfaceId, viewTag) {
    override fun getEventName(): String = name

    override fun canCoalesce(): Boolean = false

    override fun getEventData(): WritableMap = data
}

private const val MAX_PUBLIC_BRIDGE_DEPTH = 8
private const val MAX_PUBLIC_BRIDGE_NODES = 4_096
private const val MAX_PUBLIC_BRIDGE_KEYS = 64
private const val MAX_PUBLIC_BRIDGE_ITEMS = 512
private const val MAX_PUBLIC_BRIDGE_STRING_LENGTH = 256

private val LAYOUT_KEYS = setOf("schemaVersion", "id", "locale", "direction", "randomizeInputKeys", "rows", "slots")
private val THEME_KEYS = setOf("schemaVersion", "colors", "metrics", "typography", "animation", "feedback")
private val HEADLESS_KEY_PRESS_KEYS = setOf("token", "keyId")
private val NESTED_PUBLIC_KEYS = setOf(
    "schemaVersion",
    "id",
    "locale",
    "direction",
    "randomizeInputKeys",
    "rows",
    "slots",
    "header",
    "display",
    "footer",
    "error",
    "label",
    "icon",
    "role",
    "accessibilityLabel",
    "testId",
    "colors",
    "background",
    "keyBackground",
    "keyForeground",
    "keyPressedBackground",
    "keyDisabledBackground",
    "metrics",
    "keyHeight",
    "keyGap",
    "keyRadius",
    "contentPadding",
    "typography",
    "keyFontSize",
    "keyFontWeight",
    "animation",
    "pressDurationMs",
    "maskRevealDurationMs",
    "feedback",
    "haptic",
    "sound",
    "token",
    "keyId",
)

private class PublicBridgeBudget {
    private var nodes = 0

    fun visit() {
        nodes += 1
        require(nodes <= MAX_PUBLIC_BRIDGE_NODES)
    }
}

private fun ReadableMap.toPublicMap(
    allowedKeys: Set<String>,
    budget: PublicBridgeBudget = PublicBridgeBudget(),
    depth: Int = 0,
): Map<String, Any?> {
    require(depth <= MAX_PUBLIC_BRIDGE_DEPTH)
    budget.visit()
    val result = mutableMapOf<String, Any?>()
    val iterator = keySetIterator()
    var keyCount = 0
    while (iterator.hasNextKey()) {
        keyCount += 1
        require(keyCount <= MAX_PUBLIC_BRIDGE_KEYS)
        val key = iterator.nextKey()
        require(key in allowedKeys)
        result[key] = getPublicValue(key, budget, depth + 1)
    }
    return result
}

private fun ReadableArray.toPublicList(budget: PublicBridgeBudget, depth: Int): List<Any?> {
    require(depth <= MAX_PUBLIC_BRIDGE_DEPTH)
    require(size() <= MAX_PUBLIC_BRIDGE_ITEMS)
    budget.visit()
    return (0 until size()).map { index ->
        when (getType(index)) {
            ReadableType.Map -> getMap(index)?.toPublicMap(NESTED_PUBLIC_KEYS, budget, depth + 1)
            ReadableType.Array -> getArray(index)?.toPublicList(budget, depth + 1)
            ReadableType.String -> getString(index).also { requirePublicString(it, budget) }
            ReadableType.Number -> getDouble(index).also { budget.visit() }
            ReadableType.Boolean -> getBoolean(index).also { budget.visit() }
            ReadableType.Null -> null.also { budget.visit() }
        }
    }
}

private fun ReadableMap.getPublicValue(key: String, budget: PublicBridgeBudget, depth: Int): Any? = when (getType(key)) {
    ReadableType.Map -> getMap(key)?.toPublicMap(NESTED_PUBLIC_KEYS, budget, depth)
    ReadableType.Array -> getArray(key)?.toPublicList(budget, depth)
    ReadableType.String -> getString(key).also { requirePublicString(it, budget) }
    ReadableType.Number -> getDouble(key).also { budget.visit() }
    ReadableType.Boolean -> getBoolean(key).also { budget.visit() }
    ReadableType.Null -> null.also { budget.visit() }
}

private fun requirePublicString(value: String?, budget: PublicBridgeBudget) {
    budget.visit()
    if (value != null) require(value.length <= MAX_PUBLIC_BRIDGE_STRING_LENGTH)
}

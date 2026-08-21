package com.uulab.securekeypad

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.util.AttributeSet
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView

/** Public presentation role. It never contains a secret value. */
public enum class SecureKeyRole {
    INPUT,
    BACKSPACE,
    CLEAR,
    SUBMIT,
    CANCEL,
    SPACER,
}

/** A public key specification supplied by the host application. */
public data class SecureKeySpec(
    val id: String,
    val label: String,
    val role: SecureKeyRole,
    val accessibilityLabel: String = label,
)

/** A serializable row-based presentation layout. */
public data class SecureKeypadLayout(val rows: List<List<SecureKeySpec>>)

/** Theme values for the native renderer. */
public data class SecureKeypadTheme(
    val backgroundColor: Int = Color.rgb(16, 17, 20),
    val keyColor: Int = Color.rgb(35, 38, 45),
    val keyPressedColor: Int = Color.rgb(59, 130, 246),
    val keyTextColor: Int = Color.WHITE,
    val keyHeightPx: Int = 56,
    val keyGapPx: Int = 8,
    val keyRadiusPx: Float = 12f,
    val keyFontSizePx: Float = 24f,
    val contentPaddingPx: Int = 16,
)

private enum class SecureKeypadInputPolicy {
    NUMERIC,
    ASCII,
    HANGUL,
}

/** Resolves an Activity through framework ContextWrappers without assuming a host type. */
private fun Context.findActivity(): Activity? {
    var current: Context = this
    while (true) {
        if (current is Activity) return current
        val wrapper = current as? ContextWrapper ?: return null
        val base = wrapper.baseContext
        if (base === current) return null
        current = base
    }
}

/** Native-owned opaque submission. It cannot be serialized to JavaScript. */
public class SecureKeypadSubmission internal constructor(internal var handle: Long) : AutoCloseable {
    internal val isConsumed: Boolean
        get() = handle == 0L

    override fun close() {
        if (handle != 0L) {
            SecureKeypadNative.submissionFree(handle)
            handle = 0L
        }
    }

    /** Transfers the opaque capability to a native authentication consumer. */
    public fun takeNativeHandle(): Long {
        val value = handle
        handle = 0L
        return value
    }
}

/** Native-only handoff registry for framework adapters. */
public object SecureKeypadNativeSubmissionRouter {
    public typealias Consumer = (SecureKeypadSubmission) -> Boolean

    @Volatile
    private var consumer: Consumer? = null

    /** Installs the native-only consumer and replaces any previous consumer. */
    public fun install(consumer: Consumer) {
        this.consumer = consumer
    }

    /** Removes the native-only consumer. */
    public fun clear() {
        consumer = null
    }

    internal fun deliver(submission: SecureKeypadSubmission): Boolean {
        val current = consumer ?: return false
        return current(submission) && submission.isConsumed
    }
}

/**
 * Secure Native Android keypad.
 *
 * This view does not create an editable text control, does not keep a password string, and
 * exposes only masked state and an opaque native submission callback.
 */
public open class SecureKeypadView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : FrameLayout(context, attrs) {
    private var sessionHandle: Long = 0L
    private val display: TextView
    private val keypad: LinearLayout
    private val rootContainer: LinearLayout
    private var currentTheme: SecureKeypadTheme = SecureKeypadTheme()
    private var lastCancelRequest: Long? = null
    private var lastHeadlessKeyPress: Long? = null
    private var activeLayout: Map<String, SecureKeySpec> = emptyMap()
    private var headlessHostMode = false

    /** Called with a native-only submission that the host must close or authenticate natively. */
    public var onSubmit: ((SecureKeypadSubmission) -> Unit)? = null

    /** Called with masked length and non-secret display state only. */
    public var onMaskedStateChanged: ((length: Int, displayState: Int) -> Unit)? = null

    /** Called with a stable non-secret native error code. */
    public var onError: ((code: Int) -> Unit)? = null

    init {
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        isSaveEnabled = false
        requireSecureWindow()

        setBackgroundColor(currentTheme.backgroundColor)
        rootContainer = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(16, 16, 16, 16)
        }
        display = TextView(context).apply {
            gravity = Gravity.CENTER
            textSize = 24f
            setTextColor(Color.WHITE)
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_YES
            contentDescription = "No input"
        }
        keypad = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
        }
        rootContainer.addView(display, LinearLayout.LayoutParams(-1, 72))
        rootContainer.addView(keypad, LinearLayout.LayoutParams(-1, -2))
        addView(rootContainer, LayoutParams(-1, -2))
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        requireSecureWindow()
    }

    private fun requireSecureWindow() {
        val activity = context.findActivity() ?: error("secure keypad requires an Activity window")
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }

    /** Starts a numeric Secure Native session and renders the supplied layout. */
    public fun configureNumeric(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme = SecureKeypadTheme(),
        maxTokens: Int = 8,
        timeoutMs: Long = 60_000L,
    ) {
        configure(layout, theme, maxTokens, timeoutMs, SecureKeypadInputPolicy.NUMERIC)
    }

    /**
     * Selects the renderer mode. Headless host mode hides the native controls
     * and accepts only explicitly acknowledged public key-ID commands.
     */
    public fun setRendererMode(mode: String, acknowledgeLowerAssurance: Boolean) {
        require(
            (mode == "secure-native" && !acknowledgeLowerAssurance) ||
                (mode == "headless-host" && acknowledgeLowerAssurance),
        )
        headlessHostMode = mode == "headless-host"
        rootContainer.visibility = if (headlessHostMode) View.GONE else View.VISIBLE
        importantForAccessibility = if (headlessHostMode) {
            View.IMPORTANT_FOR_ACCESSIBILITY_NO_HIDE_DESCENDANTS
        } else {
            View.IMPORTANT_FOR_ACCESSIBILITY_YES
        }
    }

    /** Delivers one monotonic public key-ID command in acknowledged headless mode. */
    public fun requestHeadlessKeyPress(requestId: Long, keyId: String) {
        if (sessionHandle == 0L || !headlessHostMode || requestId < 0 ||
            !keyId.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}"))) {
            onError?.invoke(SECURE_KEYPAD_ERROR_INVALID)
            return
        }
        val previous = lastHeadlessKeyPress
        if (previous != null && requestId < previous) {
            onError?.invoke(SECURE_KEYPAD_ERROR_INVALID)
            return
        }
        if (previous == requestId) return
        val key = activeLayout[keyId]
        if (key == null) {
            onError?.invoke(SECURE_KEYPAD_ERROR_INVALID)
            return
        }
        lastHeadlessKeyPress = requestId
        activate(key)
    }

    /** Starts a printable-ASCII Secure Native session. */
    public fun configureAscii(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme = SecureKeypadTheme(),
        maxTokens: Int = 32,
        timeoutMs: Long = 60_000L,
    ) {
        configure(layout, theme, maxTokens, timeoutMs, SecureKeypadInputPolicy.ASCII)
    }

    /** Starts a structured Hangul Secure Native session. */
    public fun configureHangul(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme = SecureKeypadTheme(),
        maxTokens: Int = 32,
        timeoutMs: Long = 60_000L,
    ) {
        configure(layout, theme, maxTokens, timeoutMs, SecureKeypadInputPolicy.HANGUL)
    }

    private fun configure(
        layout: SecureKeypadLayout,
        theme: SecureKeypadTheme,
        maxTokens: Int,
        timeoutMs: Long,
        policy: SecureKeypadInputPolicy,
    ) {
        require(maxTokens in 1..4096) { "maxTokens is outside the supported range" }
        require(timeoutMs in 1..86_400_000L) { "timeoutMs is outside the supported range" }
        validateLayout(layout)
        releaseSession()
        val handle = when (policy) {
            SecureKeypadInputPolicy.NUMERIC -> SecureKeypadNative.sessionNewNumeric(maxTokens, timeoutMs)
            SecureKeypadInputPolicy.ASCII -> SecureKeypadNative.sessionNewAscii(maxTokens, timeoutMs)
            SecureKeypadInputPolicy.HANGUL -> SecureKeypadNative.sessionNewHangul(maxTokens, timeoutMs)
        }
            ?: error("secure keypad native session could not be created")
        sessionHandle = handle
        currentTheme = theme
        render(layout)
        refreshMaskedState()
    }

    /** Releases the native session and zeroizes any pending input. */
    public fun releaseSession() {
        if (sessionHandle != 0L) {
            SecureKeypadNative.sessionFree(sessionHandle)
            sessionHandle = 0L
        }
        lastHeadlessKeyPress = null
    }

    /** Cancels the native session and zeroizes any pending input. */
    public fun cancelSession() {
        if (sessionHandle == 0L) return
        val status = SecureKeypadNative.sessionCancel(sessionHandle)
        if (status != 0) onError?.invoke(status)
        refreshMaskedState()
    }

    /** Applies a monotonic, non-secret host command exactly once. */
    public fun requestCancel(requestId: Long) {
        if (requestId < 0) {
            onError?.invoke(1)
            return
        }
        val previous = lastCancelRequest
        lastCancelRequest = requestId
        if (previous != null && previous != requestId) cancelSession()
    }

    override fun onDetachedFromWindow() {
        releaseSession()
        super.onDetachedFromWindow()
    }

    override fun onWindowFocusChanged(hasWindowFocus: Boolean) {
        super.onWindowFocusChanged(hasWindowFocus)
        if (hasWindowFocus) {
            requireSecureWindow()
        } else {
            zeroizeSessionForLifecycleLoss()
        }
    }

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        if (visibility != View.VISIBLE) zeroizeSessionForLifecycleLoss()
    }

    private fun zeroizeSessionForLifecycleLoss() {
        if (sessionHandle == 0L) return
        releaseSession()
        display.text = ""
        display.contentDescription = "No input"
        onMaskedStateChanged?.invoke(0, 3)
    }

    private fun render(layout: SecureKeypadLayout) {
        activeLayout = layout.rows.flatten().associateBy { it.id }
        keypad.removeAllViews()
        setBackgroundColor(currentTheme.backgroundColor)
        rootContainer.setPadding(
            currentTheme.contentPaddingPx,
            currentTheme.contentPaddingPx,
            currentTheme.contentPaddingPx,
            currentTheme.contentPaddingPx,
        )
        display.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX, currentTheme.keyFontSizePx)
        layout.rows.forEach { row ->
            val rowView = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_HORIZONTAL
            }
            row.forEach { key ->
                val button = Button(context).apply {
                    text = key.label
                    contentDescription = key.accessibilityLabel
                    textSize = currentTheme.keyFontSizePx
                    setTextColor(currentTheme.keyTextColor)
                    background = keyBackground()
                    importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                    setOnClickListener { activate(key) }
                }
                rowView.addView(button, LinearLayout.LayoutParams(0, currentTheme.keyHeightPx, 1f).apply {
                    setMargins(currentTheme.keyGapPx / 2, currentTheme.keyGapPx / 2,
                        currentTheme.keyGapPx / 2, currentTheme.keyGapPx / 2)
                })
            }
            keypad.addView(rowView, LinearLayout.LayoutParams(-1, currentTheme.keyHeightPx + currentTheme.keyGapPx))
        }
    }

    private fun activate(key: SecureKeySpec) {
        if (sessionHandle == 0L) return
        var status = 0
        when (key.role) {
            SecureKeyRole.INPUT -> status = SecureKeypadNative.sessionPressKey(sessionHandle, key.id)
            SecureKeyRole.BACKSPACE -> status = SecureKeypadNative.sessionBackspace(sessionHandle)
            SecureKeyRole.CLEAR -> status = SecureKeypadNative.sessionClear(sessionHandle)
            SecureKeyRole.SUBMIT -> {
                val rawSubmission = SecureKeypadNative.sessionSubmit(sessionHandle) ?: return
                val submission = SecureKeypadSubmission(rawSubmission)
                deliverOrRelease(
                    submission,
                    onSubmit,
                    SecureKeypadSubmission::close,
                    { it.isConsumed },
                )
            }
            SecureKeyRole.CANCEL -> status = SecureKeypadNative.sessionCancel(sessionHandle)
            SecureKeyRole.SPACER -> return
        }
        if (status != 0) onError?.invoke(status)
        refreshMaskedState()
    }

    private fun keyBackground(): StateListDrawable = StateListDrawable().apply {
        addState(intArrayOf(android.R.attr.state_pressed), GradientDrawable().apply {
            setColor(currentTheme.keyPressedColor)
            cornerRadius = currentTheme.keyRadiusPx
        })
        addState(intArrayOf(), GradientDrawable().apply {
            setColor(currentTheme.keyColor)
            cornerRadius = currentTheme.keyRadiusPx
        })
    }

    private fun refreshMaskedState() {
        val packed = SecureKeypadNative.sessionRefresh(sessionHandle)
        val length = (packed ushr 32).toInt()
        val displayState = packed.toInt()
        if (length !in 0..SECURE_KEYPAD_MAX_RENDERED_LENGTH) {
            releaseSession()
            onError?.invoke(SECURE_KEYPAD_ERROR_INTERNAL)
            return
        }
        if (!secureKeypadIsValidDisplayState(displayState)) {
            releaseSession()
            onError?.invoke(SECURE_KEYPAD_ERROR_INTERNAL)
            return
        }
        display.text = secureKeypadMaskedDisplayText(length)
        display.contentDescription = secureKeypadAccessibilityLabel(length)
        onMaskedStateChanged?.invoke(length, displayState)
    }

    private fun validateLayout(layout: SecureKeypadLayout) {
        require(layout.rows.isNotEmpty()) { "layout must contain a row" }
        val ids = HashSet<String>()
        layout.rows.forEach { row ->
            require(row.isNotEmpty()) { "layout rows cannot be empty" }
            row.forEach { key ->
                require(key.id.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}"))) { "invalid public key ID" }
                require(ids.add(key.id)) { "duplicate public key ID" }
                require(key.label.length <= 16) { "key label is too long" }
            }
        }
    }
}

private object SecureKeypadNative {
    private var loaded: Boolean = false

    private fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("secure_keypad_jni")
            loaded = true
        }
    }

    fun sessionNewNumeric(maxTokens: Int, timeoutMs: Long): Long? {
        ensureLoaded()
        return nativeSessionNewNumeric(maxTokens, timeoutMs).takeIf { it != 0L }
    }

    fun sessionNewAscii(maxTokens: Int, timeoutMs: Long): Long? {
        ensureLoaded()
        return nativeSessionNewAscii(maxTokens, timeoutMs).takeIf { it != 0L }
    }

    fun sessionNewHangul(maxTokens: Int, timeoutMs: Long): Long? {
        ensureLoaded()
        return nativeSessionNewHangul(maxTokens, timeoutMs).takeIf { it != 0L }
    }

    fun sessionFree(handle: Long) {
        ensureLoaded()
        nativeSessionFree(handle)
    }

    fun sessionPressKey(handle: Long, keyId: String): Int {
        ensureLoaded()
        return nativeSessionPressKey(handle, keyId.toByteArray(Charsets.UTF_8))
    }

    fun sessionBackspace(handle: Long): Int {
        ensureLoaded()
        return nativeSessionBackspace(handle)
    }

    fun sessionClear(handle: Long): Int {
        ensureLoaded()
        return nativeSessionClear(handle)
    }

    fun sessionCancel(handle: Long): Int {
        ensureLoaded()
        return nativeSessionCancel(handle)
    }

    fun sessionRefresh(handle: Long): Long {
        ensureLoaded()
        return nativeSessionRefresh(handle)
    }

    fun sessionSubmit(handle: Long): Long? {
        ensureLoaded()
        return nativeSessionSubmit(handle).takeIf { it != 0L }
    }

    fun submissionFree(handle: Long) {
        ensureLoaded()
        nativeSubmissionFree(handle)
    }

    private external fun nativeSessionNewNumeric(maxTokens: Int, timeoutMs: Long): Long
    private external fun nativeSessionNewAscii(maxTokens: Int, timeoutMs: Long): Long
    private external fun nativeSessionNewHangul(maxTokens: Int, timeoutMs: Long): Long
    private external fun nativeSessionFree(handle: Long)
    private external fun nativeSessionPressKey(handle: Long, keyId: ByteArray): Int
    private external fun nativeSessionBackspace(handle: Long): Int
    private external fun nativeSessionClear(handle: Long): Int
    private external fun nativeSessionCancel(handle: Long): Int
    private external fun nativeSessionRefresh(handle: Long): Long
    private external fun nativeSessionSubmit(handle: Long): Long
    private external fun nativeSubmissionFree(handle: Long)
}

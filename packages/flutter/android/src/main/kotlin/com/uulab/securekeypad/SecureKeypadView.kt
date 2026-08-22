package com.uulab.securekeypad

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.util.AttributeSet
import android.view.Gravity
import android.view.MotionEvent
import android.view.SoundEffectConstants
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import java.security.SecureRandom
import java.util.Random

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
    val testId: String? = null,
)

public enum class SecureKeypadLayoutDirection {
    LTR,
    RTL,
}

public data class SecureKeypadSlots(
    val header: Boolean = true,
    val display: Boolean = true,
    val footer: Boolean = true,
    val error: Boolean = true,
)

public enum class SecureKeypadHapticFeedback {
    NONE,
    LIGHT,
    MEDIUM,
    HEAVY,
}

public enum class SecureKeypadSoundFeedback {
    NONE,
    CLICK,
}

/** A serializable row-based presentation layout. */
public data class SecureKeypadLayout(
    val rows: List<List<SecureKeySpec>>,
    val direction: SecureKeypadLayoutDirection = SecureKeypadLayoutDirection.LTR,
    val randomizeInputKeys: Boolean = false,
    val slots: SecureKeypadSlots = SecureKeypadSlots(),
)

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
    val keyFontWeight: Int = 600,
    val contentPaddingPx: Int = 16,
    val pressDurationMs: Long = 80L,
    val maskRevealDurationMs: Long = 0L,
    val hapticFeedback: SecureKeypadHapticFeedback = SecureKeypadHapticFeedback.LIGHT,
    val soundFeedback: SecureKeypadSoundFeedback = SecureKeypadSoundFeedback.NONE,
)

private enum class SecureKeypadInputPolicy {
    NUMERIC,
    ASCII,
    HANGUL,
}

private const val MAX_LAYOUT_ROWS = 16
private const val MAX_LAYOUT_KEYS_PER_ROW = 32
private const val MAX_LAYOUT_KEYS = 512
private const val MAX_KEY_LABEL_BYTES = 16
private const val MAX_ACCESSIBILITY_LABEL_LENGTH = 80
private val NUMERIC_INPUT_KEY_PATTERN = Regex("^digit-[0-9]$")
private val ASCII_INPUT_KEY_PATTERN = Regex("^ascii-[0-9a-f]{2}$")
private val HANGUL_INPUT_KEY_IDS = setOf(
    "jamo-giyeok", "jamo-ssang-giyeok", "jamo-nieun", "jamo-digeut", "jamo-ssang-digeut",
    "jamo-rieul", "jamo-mieum", "jamo-bieub", "jamo-ssang-bieub", "jamo-siot", "jamo-ssang-siot",
    "jamo-ieung", "jamo-jieut", "jamo-ssang-jieut", "jamo-chieut", "jamo-kieuk", "jamo-tieut",
    "jamo-pieup", "jamo-hieuh", "vowel-a", "vowel-ae", "vowel-ya", "vowel-yae", "vowel-eo",
    "vowel-e", "vowel-yeo", "vowel-ye", "vowel-o", "vowel-wa", "vowel-wae", "vowel-oe", "vowel-yo",
    "vowel-u", "vowel-wo", "vowel-we", "vowel-wi", "vowel-yu", "vowel-eu", "vowel-ui", "vowel-i",
    "tail-giyeok", "tail-ssang-giyeok", "tail-giyeok-siot", "tail-nieun", "tail-nieun-jieut",
    "tail-nieun-hieuh", "tail-digeut", "tail-rieul", "tail-rieul-giyeok", "tail-rieul-mieum",
    "tail-rieul-bieub", "tail-rieul-siot", "tail-rieul-tieut", "tail-rieul-pieup", "tail-rieul-hieuh",
    "tail-mieum", "tail-bieub", "tail-bieub-siot", "tail-siot", "tail-ssang-siot", "tail-ieung",
    "tail-jieut", "tail-chieut", "tail-kieuk", "tail-tieut", "tail-pieup", "tail-hieuh",
)

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
/** The consumer receives the originating view to bind auth state per keypad instance. */
public typealias SecureKeypadSubmissionConsumer = (SecureKeypadView, SecureKeypadSubmission) -> Boolean

public object SecureKeypadNativeSubmissionRouter {
    @Volatile
    private var consumer: SecureKeypadSubmissionConsumer? = null

    /** Installs the native-only consumer and replaces any previous consumer. */
    public fun install(consumer: SecureKeypadSubmissionConsumer) {
        this.consumer = consumer
    }

    /** Removes the native-only consumer. */
    public fun clear() {
        consumer = null
    }

    internal fun deliver(submission: SecureKeypadSubmission, from: SecureKeypadView): Boolean {
        val current = consumer ?: return false
        return deliverAndReport(
            submission,
            { candidate -> current(from, candidate) },
            SecureKeypadSubmission::close,
        ) { it.isConsumed }
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
    private val secureRandom = SecureRandom()

    /** Called with a native-only submission that the host must close or authenticate natively. */
    public var onSubmit: ((SecureKeypadSubmission) -> Unit)? = null

    /** Called with masked length and non-secret display state only. */
    public var onMaskedStateChanged: ((length: Int, displayState: Int) -> Unit)? = null

    /** Called with a stable non-secret native error code. */
    public var onError: ((code: Int) -> Unit)? = null

    /** Detaches framework callbacks so adapter teardown cannot retain this view. */
    internal fun clearBridgeCallbacks() {
        onSubmit = null
        onError = null
        onMaskedStateChanged = null
    }

    init {
        check(SecureKeypadNative.isAbiCompatible()) { "secure keypad native ABI mismatch" }
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
        validateLayout(layout, policy)
        validateTheme(theme)
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
        display.text = ""
        display.contentDescription = "No input"
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
        when (secureKeypadMonotonicCommandDecision(lastCancelRequest, requestId)) {
            SecureKeypadCommandDecision.INVALID -> onError?.invoke(SECURE_KEYPAD_ERROR_INVALID)
            SecureKeypadCommandDecision.IGNORE -> return
            SecureKeypadCommandDecision.ACCEPT -> {
                lastCancelRequest = requestId
                cancelSession()
            }
        }
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
        val layoutDirection = if (layout.direction == SecureKeypadLayoutDirection.RTL) {
            View.LAYOUT_DIRECTION_RTL
        } else {
            View.LAYOUT_DIRECTION_LTR
        }
        rootContainer.layoutDirection = layoutDirection
        keypad.layoutDirection = layoutDirection
        display.visibility = if (layout.slots.display) View.VISIBLE else View.GONE
        rootContainer.setPadding(
            currentTheme.contentPaddingPx,
            currentTheme.contentPaddingPx,
            currentTheme.contentPaddingPx,
            currentTheme.contentPaddingPx,
        )
        display.setTextSize(android.util.TypedValue.COMPLEX_UNIT_PX, currentTheme.keyFontSizePx)
        display.typeface = secureKeypadTypeface(currentTheme.keyFontWeight)
        presentationRows(layout.rows, layout.randomizeInputKeys).forEach { row ->
            val rowView = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_HORIZONTAL
            }
            row.forEach { key ->
                val button = Button(context).apply {
                    text = key.label
                    contentDescription = key.accessibilityLabel
                    textSize = currentTheme.keyFontSizePx
                    typeface = secureKeypadTypeface(currentTheme.keyFontWeight)
                    setTextColor(currentTheme.keyTextColor)
                    background = keyBackground()
                    tag = key.testId ?: key.id
                    importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
                    setOnTouchListener { view, event ->
                        when (event.actionMasked) {
                            MotionEvent.ACTION_DOWN -> view.animate()
                                .scaleX(0.98f)
                                .scaleY(0.98f)
                                .setDuration(currentTheme.pressDurationMs)
                                .start()
                            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> view.animate()
                                .scaleX(1f)
                                .scaleY(1f)
                                .setDuration(currentTheme.pressDurationMs)
                                .start()
                        }
                        false
                    }
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

    /** Reorders only input-role keys; action keys retain their configured positions. */
    private fun presentationRows(
        rows: List<List<SecureKeySpec>>,
        randomizeInputKeys: Boolean,
    ): List<List<SecureKeySpec>> {
        return secureKeypadPresentationRows(rows, randomizeInputKeys, secureRandom)
    }

    private fun activate(key: SecureKeySpec) {
        if (sessionHandle == 0L) return
        performFeedback()
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
        val (length, displayState) = secureKeypadDecodeMaskedState(packed) ?: run {
            releaseSession()
            onError?.invoke(SECURE_KEYPAD_ERROR_INTERNAL)
            return
        }
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
        val maskedText = secureKeypadMaskedDisplayText(length)
        display.animate().cancel()
        if (currentTheme.maskRevealDurationMs == 0L) {
            display.alpha = 1f
            display.text = maskedText
        } else {
            display.alpha = 0f
            display.text = maskedText
            display.animate()
                .alpha(1f)
                .setDuration(currentTheme.maskRevealDurationMs)
                .start()
        }
        display.contentDescription = secureKeypadAccessibilityLabel(length)
        onMaskedStateChanged?.invoke(length, displayState)
    }

    private fun performFeedback() {
        when (currentTheme.hapticFeedback) {
            SecureKeypadHapticFeedback.NONE -> Unit
            SecureKeypadHapticFeedback.LIGHT -> performHapticFeedback(android.view.HapticFeedbackConstants.KEYBOARD_TAP)
            SecureKeypadHapticFeedback.MEDIUM -> performHapticFeedback(android.view.HapticFeedbackConstants.VIRTUAL_KEY)
            SecureKeypadHapticFeedback.HEAVY -> performHapticFeedback(android.view.HapticFeedbackConstants.LONG_PRESS)
        }
        if (currentTheme.soundFeedback == SecureKeypadSoundFeedback.CLICK) {
            playSoundEffect(SoundEffectConstants.CLICK)
        }
    }

    private fun validateLayout(layout: SecureKeypadLayout, policy: SecureKeypadInputPolicy) {
        require(layout.rows.size in 1..MAX_LAYOUT_ROWS) { "layout row count is outside the supported range" }
        val ids = HashSet<String>()
        var totalKeys = 0
        layout.rows.forEach { row ->
            require(row.size in 1..MAX_LAYOUT_KEYS_PER_ROW) { "layout row size is outside the supported range" }
            totalKeys += row.size
            require(totalKeys <= MAX_LAYOUT_KEYS) { "layout key count is outside the supported range" }
            row.forEach { key ->
                require(key.id.matches(Regex("[a-z0-9][a-z0-9._-]{0,63}"))) { "invalid public key ID" }
                require(ids.add(key.id)) { "duplicate public key ID" }
                if (key.role == SecureKeyRole.INPUT) {
                    require(isCanonicalInputKeyId(key.id, policy)) { "input key ID does not match the selected policy" }
                }
                require(key.label.toByteArray(Charsets.UTF_8).size <= MAX_KEY_LABEL_BYTES) { "key label is too long" }
                require(key.accessibilityLabel.toByteArray(Charsets.UTF_8).size <= MAX_ACCESSIBILITY_LABEL_LENGTH) {
                    "accessibility label is too long"
                }
            }
        }
    }

    private fun isCanonicalInputKeyId(keyId: String, policy: SecureKeypadInputPolicy): Boolean {
        return when (policy) {
            SecureKeypadInputPolicy.NUMERIC -> NUMERIC_INPUT_KEY_PATTERN.matches(keyId)
            SecureKeypadInputPolicy.ASCII -> {
                ASCII_INPUT_KEY_PATTERN.matches(keyId) &&
                    keyId.substring("ascii-".length).toInt(16) in 0x20..0x7e
            }
            SecureKeypadInputPolicy.HANGUL -> HANGUL_INPUT_KEY_IDS.contains(keyId)
        }
    }

    private fun validateTheme(theme: SecureKeypadTheme) {
        require(theme.keyHeightPx in 32..160) { "key height is outside the supported range" }
        require(theme.keyGapPx in 0..48) { "key gap is outside the supported range" }
        require(theme.keyRadiusPx.isFinite() && theme.keyRadiusPx in 0f..80f) {
            "key radius is outside the supported range"
        }
        require(theme.keyFontSizePx.isFinite() && theme.keyFontSizePx in 10f..72f) {
            "key font size is outside the supported range"
        }
        require(theme.keyFontWeight in setOf(400, 500, 600, 700)) {
            "key font weight is outside the supported range"
        }
        require(theme.contentPaddingPx in 0..80) { "content padding is outside the supported range" }
        require(theme.pressDurationMs in 0L..500L) { "press duration is outside the supported range" }
        require(theme.maskRevealDurationMs in 0L..2_000L) {
            "mask reveal duration is outside the supported range"
        }
    }
}

/** Reorders only input-role keys with the caller-supplied random source. */
internal fun secureKeypadPresentationRows(
    rows: List<List<SecureKeySpec>>,
    randomizeInputKeys: Boolean,
    random: Random,
): List<List<SecureKeySpec>> {
    if (!randomizeInputKeys) return rows
    val inputKeys = rows.flatten().filter { it.role == SecureKeyRole.INPUT }.toMutableList()
    for (index in inputKeys.lastIndex downTo 1) {
        val swapIndex = random.nextInt(index + 1)
        val value = inputKeys[index]
        inputKeys[index] = inputKeys[swapIndex]
        inputKeys[swapIndex] = value
    }
    var inputIndex = 0
    return rows.map { row ->
        row.map { key ->
            if (key.role == SecureKeyRole.INPUT) inputKeys[inputIndex++] else key
        }
    }
}

private fun secureKeypadTypeface(weight: Int): Typeface = when (weight) {
    500 -> Typeface.create("sans-serif-medium", Typeface.NORMAL)
    600, 700 -> Typeface.create("sans-serif", Typeface.BOLD)
    else -> Typeface.create("sans-serif", Typeface.NORMAL)
}

private object SecureKeypadNative {
    private const val EXPECTED_ABI_VERSION = 2
    private var loaded: Boolean = false

    private fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("secure_keypad_jni")
            loaded = true
        }
    }

    fun isAbiCompatible(): Boolean {
        ensureLoaded()
        return nativeAbiVersion() == EXPECTED_ABI_VERSION
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

    private external fun nativeAbiVersion(): Int
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

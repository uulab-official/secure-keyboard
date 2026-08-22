package com.uulab.securekeypad

/**
 * Delivers an opaque native handle or releases it when no host callback is
 * installed. The host callback owns the handle after delivery. If the
 * callback throws, the handle is released before the exception is rethrown.
 */
internal fun <T> deliverOrRelease(
    value: T,
    callback: ((T) -> Unit)?,
    release: (T) -> Unit,
    isConsumed: (T) -> Boolean,
) {
    if (callback == null) {
        release(value)
    } else {
        try {
            callback(value)
        } catch (error: Throwable) {
            if (!isConsumed(value)) release(value)
            throw error
        }
    }
}

/**
 * Delivers an opaque value and reports whether the callback accepted and
 * consumed ownership. A callback failure releases an unconsumed value before
 * rethrowing, while a transferred value is never released twice.
 */
internal fun <T> deliverAndReport(
    value: T,
    callback: ((T) -> Boolean)?,
    release: (T) -> Unit,
    isConsumed: (T) -> Boolean,
): Boolean {
    if (callback == null) {
        release(value)
        return false
    }
    var accepted = false
    deliverOrRelease(
        value,
        { candidate -> accepted = callback(candidate) && isConsumed(candidate) },
        release,
        isConsumed,
    )
    return accepted
}

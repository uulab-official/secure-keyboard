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

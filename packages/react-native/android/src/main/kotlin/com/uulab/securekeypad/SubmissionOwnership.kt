package com.uulab.securekeypad

/**
 * Delivers an opaque native handle or releases it when no host callback is
 * installed. The host callback owns the handle after delivery.
 */
internal fun <T> deliverOrRelease(
    value: T,
    callback: ((T) -> Unit)?,
    release: (T) -> Unit,
) {
    if (callback == null) {
        release(value)
    } else {
        callback(value)
    }
}

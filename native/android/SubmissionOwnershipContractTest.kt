package com.uulab.securekeypad

/** Standalone contract test; run with kotlinc and a JVM, without Android. */
fun main() {
    var released = 0L
    deliverOrRelease(42L, null, { released = it })
    check(released == 42L) { "a submission without a callback must be released" }

    var received = 0L
    var incorrectlyReleased = false
    deliverOrRelease(7L, { received = it }, { incorrectlyReleased = true })
    check(received == 7L) { "a submission with a callback must be delivered" }
    check(!incorrectlyReleased) { "a delivered submission must not be released by the bridge" }
}

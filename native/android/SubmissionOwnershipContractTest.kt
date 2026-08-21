package com.uulab.securekeypad

/** Standalone contract test; run with kotlinc and a JVM, without Android. */
fun main() {
    var released = 0L
    deliverOrRelease(42L, null, { released = it }, { false })
    check(released == 42L) { "a submission without a callback must be released" }

    var received = 0L
    var incorrectlyReleased = false
    deliverOrRelease(7L, { received = it }, { incorrectlyReleased = true }, { false })
    check(received == 7L) { "a submission with a callback must be delivered" }
    check(!incorrectlyReleased) { "a delivered submission must not be released by the bridge" }

    var releasedAfterFailure = false
    var caught = false
    try {
        deliverOrRelease(9L, { error("consumer failed") }, { releasedAfterFailure = true }, { false })
    } catch (_: IllegalStateException) {
        caught = true
    }
    check(caught) { "a consumer failure must remain observable to the host" }
    check(releasedAfterFailure) { "a failed consumer must not retain an opaque submission" }

    data class OwnedHandle(var handle: Long)
    val transferred = OwnedHandle(11L)
    var releasedAfterTransfer = false
    caught = false
    try {
        deliverOrRelease(
            transferred,
            { owner ->
                owner.handle = 0L
                error("consumer failed after transfer")
            },
            { releasedAfterTransfer = true },
            { owner -> owner.handle == 0L },
        )
    } catch (_: IllegalStateException) {
        caught = true
    }
    check(caught) { "a post-transfer consumer failure must remain observable" }
    check(!releasedAfterTransfer) { "a transferred handle must not be released twice" }
}

package eu.opencloud.android.next.ui

import android.os.SystemClock

/** Memory-only exception for a user-launched document picker, never a general background unlock. */
internal class VaultPickerLease(
    private val clock: () -> Long = SystemClock::elapsedRealtime,
) {
    private var deadline: Long? = null

    fun arm() {
        deadline = clock() + DURATION_MS
    }

    fun remainingMillis(): Long {
        val expires = deadline ?: return 0
        return (expires - clock()).coerceAtLeast(0)
    }

    fun clear() {
        deadline = null
    }

    companion object {
        const val DURATION_MS = 120_000L
    }
}

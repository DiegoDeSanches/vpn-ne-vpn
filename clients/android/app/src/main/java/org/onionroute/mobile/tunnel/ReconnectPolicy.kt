package org.onionroute.mobile.tunnel

import kotlin.math.min

/** Bounded reconnect delay; power saving changes availability, never safety. */
class ReconnectPolicy {
    fun delayMs(attempt: Int, powerSave: Boolean, expensive: Boolean, constrained: Boolean): Long {
        val boundedAttempt = attempt.coerceIn(0, 8)
        val exponential = min(60_000L, 1_000L shl boundedAttempt)
        val multiplier = when {
            powerSave || constrained -> 4L
            expensive -> 2L
            else -> 1L
        }
        return min(5 * 60_000L, exponential * multiplier)
    }
}


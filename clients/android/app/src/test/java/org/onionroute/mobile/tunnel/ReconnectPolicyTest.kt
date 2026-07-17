package org.onionroute.mobile.tunnel

import org.junit.Assert.assertEquals
import org.junit.Test

class ReconnectPolicyTest {
    private val policy = ReconnectPolicy()

    @Test
    fun powerSavingSlowsButDoesNotDisableReconnect() {
        assertEquals(1_000L, policy.delayMs(0, powerSave = false, expensive = false, constrained = false))
        assertEquals(4_000L, policy.delayMs(0, powerSave = true, expensive = false, constrained = false))
    }

    @Test
    fun backoffIsBounded() {
        assertEquals(240_000L, policy.delayMs(99, powerSave = true, expensive = true, constrained = true))
    }
}


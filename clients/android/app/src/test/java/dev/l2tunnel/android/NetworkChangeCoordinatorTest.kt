package dev.l2tunnel.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkChangeCoordinatorTest {
    @Test
    fun debouncesTransitionsAndEnforcesSlidingWindowBudget() {
        val coord = NetworkChangeCoordinator(
            debounceMs = 1_500L,
            windowMs = 60_000L,
            maxReconnectsPerWindow = 2,
        )

        // Initial network registration does not trigger reconnect.
        assertFalse(coord.onNetworkAvailable(100L, 1_000L))
        // Same network repeated does not trigger reconnect.
        assertFalse(coord.onNetworkAvailable(100L, 5_000L))

        // Switch from Wi-Fi (100) to 5G (200) triggers reconnect #1.
        assertTrue(coord.onNetworkAvailable(200L, 10_000L))
        assertEquals(1, coord.remainingBudget(10_000L))

        // Rapid flap inside 1500 ms debounce window is suppressed.
        assertFalse(coord.onNetworkAvailable(300L, 11_000L))

        // Transition after debounce window triggers reconnect #2 (budget now 0).
        assertTrue(coord.onNetworkAvailable(400L, 13_000L))
        assertEquals(0, coord.remainingBudget(13_000L))

        // Further transition inside the 60 s sliding window is capped.
        assertFalse(coord.onNetworkAvailable(500L, 20_000L))

        // After window elapses, budget recovers cleanly.
        assertTrue(coord.onNetworkAvailable(600L, 75_000L))
    }

    @Test
    fun networkLossAndRecoveryTriggersReconnectOnceOnline() {
        val coord = NetworkChangeCoordinator(debounceMs = 1_000L)
        assertFalse(coord.onNetworkAvailable(100L, 0L))
        coord.onNetworkLost(100L)
        // Even if the same handle returns after loss, reconnect triggers cleanly.
        assertTrue(coord.onNetworkAvailable(100L, 2_000L))
    }
}

package dev.l2tunnel.android

/**
 * Pure, clock-injected network-change coordinator for Android Wi-Fi / cellular transitions (CL-30).
 *
 * Prevents duplicate tunnels, route loops, and battery-draining reconnect storms by:
 * - Ignoring initial network registration (only acting when the active network handle changes).
 * - Debouncing rapid link transitions (`debounceMs`, default 1500 ms).
 * - Capping automatic network-change reconnects inside a sliding window (`maxReconnectsPerWindow`
 *   per `windowMs`, default 6 reconnects per 5 minutes).
 */
class NetworkChangeCoordinator(
    private val debounceMs: Long = 1_500L,
    private val windowMs: Long = 300_000L,
    private val maxReconnectsPerWindow: Int = 6,
) {
    private var activeNetworkId: Long? = null
    private var lastTriggerMs: Long? = null
    private val recentTriggers = ArrayDeque<Long>()

    /**
     * Evaluate a default-network change event at monotonic `nowMs`.
     * Returns `true` if a Local API v5 reconnect should be scheduled.
     */
    @Synchronized
    fun onNetworkAvailable(networkId: Long, nowMs: Long): Boolean {
        val previous = activeNetworkId
        activeNetworkId = networkId
        if (previous == null || previous == networkId) {
            return false
        }
        val last = lastTriggerMs
        if (last != null && nowMs - last < debounceMs) {
            return false
        }
        pruneWindow(nowMs)
        if (recentTriggers.size >= maxReconnectsPerWindow) {
            return false
        }
        lastTriggerMs = nowMs
        recentTriggers.addLast(nowMs)
        return true
    }

    /** Record network loss without triggering an immediate reconnect while offline. */
    @Synchronized
    fun onNetworkLost(networkId: Long) {
        if (activeNetworkId == networkId) {
            // Keep activeNetworkId as sentinel (-1L) so the next available network triggers
            // a clean reconnect once connectivity returns.
            activeNetworkId = -1L
        }
    }

    /** Reset state on explicit user disconnect or service teardown. */
    @Synchronized
    fun reset() {
        activeNetworkId = null
        lastTriggerMs = null
        recentTriggers.clear()
    }

    @Synchronized
    fun remainingBudget(nowMs: Long): Int {
        pruneWindow(nowMs)
        return (maxReconnectsPerWindow - recentTriggers.size).coerceAtLeast(0)
    }

    private fun pruneWindow(nowMs: Long) {
        while (recentTriggers.isNotEmpty() && nowMs - recentTriggers.first() >= windowMs) {
            recentTriggers.removeFirst()
        }
    }
}

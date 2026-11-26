package dev.l2tunnel.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.l2tunnel.android.TuningSettingSnapshot
import dev.l2tunnel.android.VpnUiState

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ConnectionScreen(
    state: VpnUiState,
    isWideLayout: Boolean,
    onSwitchCover: (String) -> Unit,
    onTuningSwitch: (TuningSettingSnapshot) -> Unit,
    onRateBudgetSet: (Long, Long) -> Unit,
    onTestPing: (Int) -> Unit,
    onTestSpeed: (String, Int, Int) -> Unit,
    onTestCancel: (Long) -> Unit,
) {
    val scroll = rememberScrollState()
    val connected = state.running && state.phase == "connected"
    val ratePresetsMbps = listOf(10, 50, 100, 200, 500, 1000)
    var selectedRateMbps by remember(state.sendRateBytesPerSec) {
        val currentMbps = ((state.sendRateBytesPerSec ?: 12_500_000L) * 8L / 1_000_000L).toInt()
        mutableIntStateOf(ratePresetsMbps.minByOrNull { kotlin.math.abs(it - currentMbps) } ?: 100)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (!connected) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Connect the tunnel in Overview to use live make-before-break cover switching, FEC/MTU tuning, speed budgets, and in-process tunnel tests.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(16.dp),
                )
            }
        }

        if (isWideLayout) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    UdpCoverSwitchCard(state = state, connected = connected, onSwitchCover = onSwitchCover)
                    LiveTuningCard(state = state, connected = connected, onTuningSwitch = onTuningSwitch)
                }
                Column(
                    modifier = Modifier.weight(1f),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    SpeedBudgetCard(
                        state = state,
                        connected = connected,
                        ratePresetsMbps = ratePresetsMbps,
                        selectedRateMbps = selectedRateMbps,
                        onSelectRate = { mbps ->
                            selectedRateMbps = mbps
                            val bps = mbps.toLong() * 1_000_000L / 8L
                            onRateBudgetSet(bps, bps)
                        },
                    )
                    TunnelTestCard(
                        state = state,
                        connected = connected,
                        onTestPing = onTestPing,
                        onTestSpeed = onTestSpeed,
                        onTestCancel = onTestCancel,
                    )
                }
            }
        } else {
            UdpCoverSwitchCard(state = state, connected = connected, onSwitchCover = onSwitchCover)
            LiveTuningCard(state = state, connected = connected, onTuningSwitch = onTuningSwitch)
            SpeedBudgetCard(
                state = state,
                connected = connected,
                ratePresetsMbps = ratePresetsMbps,
                selectedRateMbps = selectedRateMbps,
                onSelectRate = { mbps ->
                    selectedRateMbps = mbps
                    val bps = mbps.toLong() * 1_000_000L / 8L
                    onRateBudgetSet(bps, bps)
                },
            )
            TunnelTestCard(
                state = state,
                connected = connected,
                onTestPing = onTestPing,
                onTestSpeed = onTestSpeed,
                onTestCancel = onTestCancel,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun UdpCoverSwitchCard(
    state: VpnUiState,
    connected: Boolean,
    onSwitchCover: (String) -> Unit,
) {
    val covers = listOf("quic-like" to "QUIC-like", "media-like" to "Media-like", "tls-like" to "TLS-like")
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = "Live UDP Cover Switch (Make-Before-Break)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = "Opens a protected standby UDP socket, probes the peer, and cuts over seamlessly without dropping the session.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                covers.forEachIndexed { idx, (id, label) ->
                    val active = state.cover == id
                    SegmentedButton(
                        selected = active,
                        onClick = { if (connected && !active) onSwitchCover(id) },
                        enabled = connected,
                        shape = SegmentedButtonDefaults.itemShape(index = idx, count = covers.size),
                        label = { Text(label) },
                    )
                }
            }
            Text(
                text = "Active cover: ${state.cover ?: "—"} · Peer: ${state.peer ?: "—"} · Switches: ${state.carrierSwitches}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun LiveTuningCard(
    state: VpnUiState,
    connected: Boolean,
    onTuningSwitch: (TuningSettingSnapshot) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = "Live FEC Repair & MTU Tuning",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            val tuning = state.tuning
            if (tuning == null || tuning.entries.isEmpty()) {
                Text(
                    text = if (connected) {
                        "No live-tuning catalog entries reported for this session (add tune_repair in the profile)."
                    } else {
                        "Available while connected to a tunable Swift profile."
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                val cur = tuning.current ?: tuning.entries.first()
                Text(
                    text = "Current: repair=${cur.repair} · device MTU=${cur.deviceMtu} · path MTU=${cur.pathMtu}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text("FEC repair ratio", style = MaterialTheme.typography.labelMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    tuning.repairChoices.forEach { repair ->
                        val target = tuning.entries.firstOrNull {
                            it.repair == repair && it.deviceMtu == cur.deviceMtu
                        } ?: tuning.entries.firstOrNull { it.repair == repair }
                        FilterChip(
                            selected = cur.repair == repair,
                            enabled = connected && target != null,
                            onClick = { if (target != null) onTuningSwitch(target) },
                            label = { Text(repair) },
                        )
                    }
                }
                if (tuning.deviceMtuChoices.size > 1) {
                    Text("TUN MTU", style = MaterialTheme.typography.labelMedium)
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        tuning.deviceMtuChoices.forEach { mtu ->
                            val target = tuning.entries.firstOrNull {
                                it.repair == cur.repair && it.deviceMtu == mtu
                            } ?: tuning.entries.firstOrNull { it.deviceMtu == mtu }
                            FilterChip(
                                selected = cur.deviceMtu == mtu,
                                enabled = connected && target != null,
                                onClick = { if (target != null) onTuningSwitch(target) },
                                label = { Text("$mtu B") },
                            )
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SpeedBudgetCard(
    state: VpnUiState,
    connected: Boolean,
    ratePresetsMbps: List<Int>,
    selectedRateMbps: Int,
    onSelectRate: (Int) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = "Live Wire Speed Budget (RateBudgetV1)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            val curSend = state.sendRateBytesPerSec?.let { Formatters.rateBits(it * 8.0) } ?: "—"
            val curRecv = state.receiveRateBytesPerSec?.let { Formatters.rateBits(it * 8.0) } ?: "—"
            Text(
                text = "Effective TX / RX budget: $curSend / $curRecv",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                ratePresetsMbps.forEach { mbps ->
                    FilterChip(
                        selected = selectedRateMbps == mbps,
                        enabled = connected,
                        onClick = { onSelectRate(mbps) },
                        label = { Text("$mbps Mbps") },
                    )
                }
            }
        }
    }
}

@Composable
private fun TunnelTestCard(
    state: VpnUiState,
    connected: Boolean,
    onTestPing: (Int) -> Unit,
    onTestSpeed: (String, Int, Int) -> Unit,
    onTestCancel: (Long) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                text = "In-Process Tunnel Test (TunnelTestV1)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = "Runs authenticated ICMP ping or 4-stream TCP speed tests inside the encrypted tunnel without touching host routing.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val test = state.tunnelTest
            val testRunning = test?.state == "running"
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                FilledTonalButton(
                    onClick = { onTestPing(5) },
                    enabled = connected && !testRunning,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Ping (5)")
                }
                Button(
                    onClick = { onTestSpeed("download", 4, 4000) },
                    enabled = connected && !testRunning,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Download")
                }
                FilledTonalButton(
                    onClick = { onTestSpeed("upload", 4, 4000) },
                    enabled = connected && !testRunning,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Upload")
                }
            }
            if (test != null && testRunning) {
                OutlinedButton(onClick = { onTestCancel(test.id) }) {
                    Text("Cancel Test #${test.id}")
                }
            }
            if (test != null) {
                Spacer(Modifier.height(2.dp))
                val summary = if (test.ping != null) {
                    val p = test.ping
                    "Test #${test.id} (${test.state}): ${p.received}/${p.sent} replies · " +
                        "RTT min/avg/max ${Formatters.rttMicros(p.minUs)} / ${Formatters.rttMicros(p.avgUs)} / ${Formatters.rttMicros(p.maxUs)}"
                } else {
                    "Test #${test.id} (${test.direction ?: test.kind}, ${test.state}): " +
                        "${Formatters.rateBits(test.bitsPerSecond.toDouble())} · " +
                        "${Formatters.bytes(test.bytes)} in ${String.format("%.1f s", test.elapsedMs / 1000.0)}"
                }
                Text(
                    text = summary,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                )
                if (!test.error.isNullOrBlank()) {
                    Text(
                        text = "Error: ${test.error}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

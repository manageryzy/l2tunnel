package dev.l2tunnel.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import dev.l2tunnel.android.DiagnosticsExporter
import dev.l2tunnel.android.VpnUiState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun StatsScreen(
    state: VpnUiState,
    onExportDiagnostics: (Boolean) -> Unit,
) {
    val scroll = rememberScrollState()
    var redactEndpoints by remember { mutableStateOf(true) }
    val timeFmt = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // 1. Live Throughput & RTT Charts
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = "Rolling Wire Throughput & RTT (Last ${state.history.size} samples)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                val txValues = state.history.map { it.txBytesPerSec }
                val rttValues = state.history.mapNotNull { it.rttMs }
                Text(
                    text = "Wire TX: ${Formatters.rateBytesPerSec(state.txBytesPerSec)} · RTT: ${Formatters.rttMicros(state.rttMicros)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                LineChart(
                    values = txValues,
                    color = MaterialTheme.colorScheme.primary,
                    minMaxFloor = 1024f,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(84.dp),
                )
                if (rttValues.size >= 2) {
                    Text(
                        text = "Session RTT (ms) · min ${String.format("%.2f", rttValues.min())} / max ${String.format("%.2f", rttValues.max())} ms",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    LineChart(
                        values = rttValues,
                        color = MaterialTheme.colorScheme.tertiary,
                        minMaxFloor = 1f,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(64.dp),
                    )
                }
            }
        }

        // 2. Wire & TUN Counters
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Text(
                    text = "Transport & TUN Counters",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                StatRow("Wire Sent", "${Formatters.bytes(state.wireSentBytes)} (${state.wireSentPackets} pkts)")
                StatRow("Wire Received", "${state.wireReceivedPackets} pkts")
                StatRow("Socket Drops / Rx Errors", "${state.wireSendDrops} / ${state.wireReceiveErrors}")
                StatRow("Rejected / Replay", "${state.wireRejectedPackets} / ${state.wireReplayRejections}")
                StatRow("TUN Read / Written", "${state.nativeReadPackets} / ${state.nativeWrittenPackets} pkts")
                StatRow("TUN Backpressure Drops", "${state.nativeBackpressureDrops}")
            }
        }

        // 3. Local CSR Meters (meters_read)
        if (state.meters.isNotEmpty()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        text = "Local CSR Meters (${state.meters.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Spacer(Modifier.height(4.dp))
                    state.meters.take(24).forEach { m ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = m.path,
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.weight(1f),
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = m.value.toString(),
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                            )
                        }
                    }
                }
            }
        }

        // 4. Redacted Diagnostics Export (CL-16)
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Diagnostics & Bounded Event Log",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = redactEndpoints,
                        onCheckedChange = { redactEndpoints = it },
                    )
                    Text(
                        text = "Redact IP endpoints (private keys are always excluded)",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Button(onClick = { onExportDiagnostics(redactEndpoints) }) {
                    Icon(Icons.Filled.Download, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Export Diagnostics JSON")
                }
                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                if (state.events.isEmpty()) {
                    Text(
                        text = "No events recorded yet.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    state.events.takeLast(40).asReversed().forEach { ev ->
                        val msg = if (redactEndpoints) {
                            DiagnosticsExporter.redactAddresses(ev.message)
                        } else {
                            ev.message
                        }
                        Text(
                            text = "[${timeFmt.format(Date(ev.timestampMs))}] ${ev.source}: $msg",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
        )
    }
}

@Composable
private fun LineChart(
    values: List<Float>,
    color: Color,
    minMaxFloor: Float,
    modifier: Modifier = Modifier,
) {
    Canvas(modifier = modifier) {
        drawLine(
            color = color.copy(alpha = 0.2f),
            start = Offset(0f, size.height - 1f),
            end = Offset(size.width, size.height - 1f),
        )
        if (values.size < 2) return@Canvas
        val peak = (values.maxOrNull() ?: minMaxFloor).coerceAtLeast(minMaxFloor)
        val stepX = size.width / (values.size - 1).coerceAtLeast(1)
        val strokePath = Path()
        val fillPath = Path()
        values.forEachIndexed { idx, v ->
            val x = idx * stepX
            val y = size.height - (v / peak).coerceIn(0f, 1f) * (size.height - 8f) - 4f
            if (idx == 0) {
                strokePath.moveTo(x, y)
                fillPath.moveTo(x, size.height)
                fillPath.lineTo(x, y)
            } else {
                strokePath.lineTo(x, y)
                fillPath.lineTo(x, y)
            }
        }
        fillPath.lineTo(size.width, size.height)
        fillPath.close()
        drawPath(fillPath, color = color.copy(alpha = 0.14f))
        drawPath(strokePath, color = color, style = Stroke(width = 3f, cap = StrokeCap.Round))
    }
}

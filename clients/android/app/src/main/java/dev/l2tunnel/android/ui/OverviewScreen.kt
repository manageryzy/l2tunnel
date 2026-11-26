package dev.l2tunnel.android.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.l2tunnel.android.SplitTunnelMode
import dev.l2tunnel.android.StoredProfileSummary
import dev.l2tunnel.android.VpnUiState

@Composable
fun OverviewScreen(
    state: VpnUiState,
    profiles: List<StoredProfileSummary>,
    activeProfile: StoredProfileSummary?,
    inlineError: String?,
    onSelectProfile: (String) -> Unit,
    onConnect: () -> Unit,
    onReconnect: () -> Unit,
    onDisconnect: () -> Unit,
    onOpenProfilesTab: () -> Unit,
) {
    val scroll = rememberScrollState()
    var profileMenuOpen by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // Hero connection card
        val connected = state.running && state.phase == "connected"
        val containerColor = when {
            connected -> MaterialTheme.colorScheme.primaryContainer
            state.phase == "failed" -> MaterialTheme.colorScheme.errorContainer
            state.running -> MaterialTheme.colorScheme.secondaryContainer
            else -> MaterialTheme.colorScheme.surfaceVariant
        }
        val contentColor = when {
            connected -> MaterialTheme.colorScheme.onPrimaryContainer
            state.phase == "failed" -> MaterialTheme.colorScheme.onErrorContainer
            state.running -> MaterialTheme.colorScheme.onSecondaryContainer
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = containerColor, contentColor = contentColor),
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = if (connected) Icons.Filled.Shield else Icons.Filled.PowerSettingsNew,
                            contentDescription = null,
                            modifier = Modifier.size(28.dp),
                        )
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(
                                text = state.headline,
                                style = MaterialTheme.typography.headlineSmall,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text(
                                text = "Phase: ${state.phase}" +
                                    (if (state.cover != null) " · ${state.cover}" else ""),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }

                    // Active profile selector pill
                    Box {
                        AssistChip(
                            onClick = { profileMenuOpen = true },
                            label = {
                                Text(
                                    text = activeProfile?.id ?: "No profile",
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                            },
                            trailingIcon = {
                                Icon(Icons.Filled.ArrowDropDown, contentDescription = "Select profile")
                            },
                        )
                        DropdownMenu(
                            expanded = profileMenuOpen,
                            onDismissRequest = { profileMenuOpen = false },
                        ) {
                            if (profiles.isEmpty()) {
                                DropdownMenuItem(
                                    text = { Text("Import or create a profile…") },
                                    onClick = {
                                        profileMenuOpen = false
                                        onOpenProfilesTab()
                                    },
                                )
                            } else {
                                profiles.forEach { p ->
                                    DropdownMenuItem(
                                        text = {
                                            Text(
                                                text = p.id + if (p.isValid) "" else " (incomplete)",
                                                fontWeight = if (p.id == activeProfile?.id) FontWeight.Bold else FontWeight.Normal,
                                            )
                                        },
                                        onClick = {
                                            profileMenuOpen = false
                                            onSelectProfile(p.id)
                                        },
                                    )
                                }
                            }
                        }
                    }
                }

                if (!inlineError.isNullOrBlank()) {
                    Surface(
                        color = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        shape = MaterialTheme.shapes.small,
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(Icons.Filled.Warning, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(text = inlineError, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                } else if (!state.detail.isNullOrBlank()) {
                    Text(
                        text = state.detail,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    if (!state.running) {
                        Button(
                            onClick = onConnect,
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(Icons.Filled.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Connect")
                        }
                    } else {
                        Button(
                            onClick = onDisconnect,
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.error,
                                contentColor = MaterialTheme.colorScheme.onError,
                            ),
                        ) {
                            Icon(Icons.Filled.PowerSettingsNew, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text("Disconnect")
                        }
                        FilledTonalButton(onClick = onReconnect) {
                            Icon(Icons.Filled.Refresh, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Reconnect")
                        }
                    }
                }
            }
        }

        // Live metrics 2x2 grid
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            MetricTile(
                modifier = Modifier.weight(1f),
                label = "Peer Endpoint",
                value = state.peer ?: activeProfile?.profile?.udpPeer ?: "—",
                sub = if (state.carrierSwitches > 0) "${state.carrierSwitches} cover switch(es)" else "UDP · Dynamic NAT",
            )
            MetricTile(
                modifier = Modifier.weight(1f),
                label = "Session RTT",
                value = Formatters.rttMicros(state.rttMicros),
                sub = "UDP cover: ${state.cover ?: activeProfile?.profile?.cover ?: "—"}",
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            MetricTile(
                modifier = Modifier.weight(1f),
                label = "Wire TX Rate",
                value = Formatters.rateBytesPerSec(state.txBytesPerSec),
                sub = "Total: ${Formatters.bytes(state.wireSentBytes)}",
            )
            MetricTile(
                modifier = Modifier.weight(1f),
                label = "Wire RX Activity",
                value = String.format("%.0f pkt/s", state.rxPacketsPerSec),
                sub = "Total: ${state.wireReceivedPackets} pkts",
            )
        }

        // Compact live TX sparkline
        if (state.history.size >= 2) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "Live Wire TX Throughput",
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Spacer(Modifier.height(8.dp))
                    val lineColor = MaterialTheme.colorScheme.primary
                    val values = state.history.map { it.txBytesPerSec }
                    val peak = (values.maxOrNull() ?: 1f).coerceAtLeast(1024f)
                    Canvas(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(64.dp),
                    ) {
                        val stepX = size.width / (values.size - 1).coerceAtLeast(1)
                        val path = Path()
                        values.forEachIndexed { idx, v ->
                            val x = idx * stepX
                            val y = size.height - (v / peak).coerceIn(0f, 1f) * (size.height - 6f) - 3f
                            if (idx == 0) path.moveTo(x, y) else path.lineTo(x, y)
                        }
                        drawPath(path, color = lineColor, style = Stroke(width = 3f, cap = StrokeCap.Round))
                        drawLine(
                            color = lineColor.copy(alpha = 0.2f),
                            start = Offset(0f, size.height - 1f),
                            end = Offset(size.width, size.height - 1f),
                        )
                    }
                    Text(
                        text = "Peak window: ${Formatters.rateBytesPerSec(peak)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }

        // Active profile & platform capability strip
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.Lock,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Android VpnService Capability & Security",
                        style = MaterialTheme.typography.titleSmall,
                    )
                }
                val prof = activeProfile?.profile
                if (prof != null) {
                    val splitDesc = when (prof.splitTunnelMode) {
                        SplitTunnelMode.ALL -> "All apps (self-excluded)"
                        SplitTunnelMode.EXCLUDE -> "Exclude ${prof.splitTunnelApps.size} app(s)"
                        SplitTunnelMode.INCLUDE -> "Only ${prof.splitTunnelApps.size} app(s)"
                    }
                    Text(
                        text = "TUN ${prof.tunAddress}/${prof.tunPrefixLength} · MTU ${prof.tunMtu} · Split: $splitDesc",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        text = if (activeProfile.keystoreSealed) {
                            "Private keys encrypted at rest with Android Keystore (AES-256-GCM)."
                        } else {
                            "Profile has unsealed key files — seal under Android Keystore in Profiles & Keys."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Text(
                        text = "No valid profile selected. Import a .zip profile bundle or configure one in Profiles & Keys.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedButton(onClick = onOpenProfilesTab) {
                        Text("Open Profiles & Keys")
                    }
                }
                Text(
                    text = "Layer: TUN (L3) only · VpnService.protect() active on initial, reconnect, and standby sockets. TAP/VXLAN L2 is unsupported on standard Android VpnService.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

@Composable
fun MetricTile(
    label: String,
    value: String,
    sub: String,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = sub,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

package dev.l2tunnel.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import dev.l2tunnel.android.AndroidVpnProfile
import dev.l2tunnel.android.IpGeoAsnDatabase
import dev.l2tunnel.android.RedirectAction
import dev.l2tunnel.android.RedirectPolicy
import dev.l2tunnel.android.RedirectRule
import dev.l2tunnel.android.RuleMatcher

/**
 * Adaptive Material 3 editor for detailed IP redirect rules (CIDR, ASN, GeoIP IP location,
 * Continent, Private/LAN) with built-in offline GeoIP/ASN lookup tester and compiled TUN route preview.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun RedirectRulesDialog(
    profileId: String,
    initial: AndroidVpnProfile,
    isWideLayout: Boolean,
    onDismiss: () -> Unit,
    onSave: (RedirectPolicy) -> Unit,
) {
    val db = remember { IpGeoAsnDatabase.builtin() }
    val initPolicy = initial.redirectPolicy ?: RedirectPolicy(enabled = false)
    var enabled by remember(profileId) { mutableStateOf(initPolicy.enabled) }
    var defaultAction by remember(profileId) { mutableStateOf(initPolicy.defaultAction) }
    var rules by remember(profileId) { mutableStateOf(initPolicy.rules) }
    var newMatcherText by remember { mutableStateOf("") }
    var newAction by remember { mutableStateOf(RedirectAction.DIRECT) }
    var addError by remember { mutableStateOf<String?>(null) }
    var testIpText by remember { mutableStateOf("114.114.114.114") }

    val draftPolicy = RedirectPolicy(
        enabled = enabled,
        defaultAction = defaultAction,
        bypassPeerEndpoint = true,
        rules = rules,
    )
    val compiled = remember(draftPolicy, initial.udpPeer, initial.routes) {
        if (draftPolicy.enabled) {
            draftPolicy.compileIpv4Routes(
                db = db,
                peerHost = initial.udpPeer,
                alwaysIncludeCidrs = initial.routes,
            )
        } else {
            null
        }
    }
    val testDecision = remember(draftPolicy, testIpText) {
        val trimmed = testIpText.trim()
        if (trimmed.isEmpty()) null else draftPolicy.evaluate(trimmed, db)
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth(if (isWideLayout) 0.86f else 0.94f)
            .widthIn(max = 840.dp),
        title = { Text("Redirect Rules (GeoIP / ASN / CIDR): $profileId") },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = if (isWideLayout) 400.dp else 520.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Enable rule-based IP redirect", style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = "Compiles exact TUN routes via CIDR subtraction (peer IP always excluded; ${db.size} offline GeoIP/ASN prefixes).",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = enabled, onCheckedChange = { enabled = it })
                }

                Text("Quick Presets", style = MaterialTheme.typography.labelMedium)
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    RedirectPolicy.PRESET_NAMES.forEach { (id, label) ->
                        OutlinedButton(
                            onClick = {
                                val p = RedirectPolicy.preset(id)
                                enabled = p.enabled
                                defaultAction = p.defaultAction
                                rules = p.rules
                                addError = null
                            },
                        ) { Text(label, style = MaterialTheme.typography.labelSmall) }
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("Default action:", style = MaterialTheme.typography.labelMedium)
                    listOf(RedirectAction.TUNNEL, RedirectAction.DIRECT).forEach { act ->
                        FilterChip(
                            selected = defaultAction == act,
                            onClick = { defaultAction = act },
                            label = { Text(act.wire.uppercase()) },
                        )
                    }
                }

                // Add rule row
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        value = newMatcherText,
                        onValueChange = {
                            newMatcherText = it
                            addError = null
                        },
                        label = { Text("Rule (geoip:CN, asn:13335, continent:EU, 10.0.0.0/8, lan)") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    FilterChip(
                        selected = true,
                        onClick = {
                            newAction = when (newAction) {
                                RedirectAction.DIRECT -> RedirectAction.TUNNEL
                                RedirectAction.TUNNEL -> RedirectAction.REJECT
                                RedirectAction.REJECT -> RedirectAction.DIRECT
                            }
                        },
                        label = { Text(newAction.wire.uppercase()) },
                    )
                    Button(
                        onClick = {
                            try {
                                val matcher = RuleMatcher.parseShorthand(newMatcherText)
                                val nextId = "rule-${rules.size + 1}"
                                rules = rules + RedirectRule(nextId, true, matcher, newAction)
                                enabled = true
                                newMatcherText = ""
                                addError = null
                            } catch (e: Exception) {
                                addError = e.message ?: "Invalid rule"
                            }
                        },
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Add")
                    }
                }
                if (!addError.isNullOrBlank()) {
                    Text(addError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }

                // Ordered rules list
                if (rules.isNotEmpty()) {
                    Text("Ordered Rules (${rules.size}, first match wins)", style = MaterialTheme.typography.labelMedium)
                    rules.forEachIndexed { idx, rule ->
                        Surface(
                            color = MaterialTheme.colorScheme.surfaceVariant,
                            shape = MaterialTheme.shapes.small,
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 10.dp, vertical = 6.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "${idx + 1}. ${rule.matcher.label()} -> ${rule.action.wire.uppercase()}",
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.Medium,
                                        fontFamily = FontFamily.Monospace,
                                    )
                                    if (!rule.comment.isNullOrBlank()) {
                                        Text(
                                            text = rule.comment,
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                }
                                Switch(
                                    checked = rule.enabled,
                                    onCheckedChange = { checked ->
                                        rules = rules.mapIndexed { i, r ->
                                            if (i == idx) r.copy(enabled = checked) else r
                                        }
                                    },
                                )
                                IconButton(onClick = { rules = rules.filterIndexed { i, _ -> i != idx } }) {
                                    Icon(Icons.Filled.Delete, contentDescription = "Delete rule", modifier = Modifier.size(18.dp))
                                }
                            }
                        }
                    }
                }

                // Live IP lookup & rule tester
                Surface(
                    color = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.6f),
                    shape = MaterialTheme.shapes.small,
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth().padding(10.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text("Live IP Lookup & Rule Tester", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            OutlinedTextField(
                                value = testIpText,
                                onValueChange = { testIpText = it },
                                label = { Text("Test IPv4") },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                            )
                            listOf("114.114.114.114", "1.1.1.1", "8.8.8.8", "192.168.1.1").forEach { sample ->
                                OutlinedButton(onClick = { testIpText = sample }) {
                                    Text(sample.substringBefore('.') + "…", style = MaterialTheme.typography.labelSmall)
                                }
                            }
                        }
                        testDecision?.let { d ->
                            val geoStr = d.geo?.let { g ->
                                "${g.country}${g.region?.let { "-$it" } ?: ""} (${g.continent}) · AS${g.asn} ${g.org}"
                            } ?: "No GeoIP/ASN entry"
                            Text(
                                text = "Decision: ${d.action.wire.uppercase()} via ${d.matchedBy} (${d.matchedRuleId}) | $geoStr",
                                style = MaterialTheme.typography.labelSmall,
                                fontFamily = FontFamily.Monospace,
                            )
                        }
                        compiled?.let { c ->
                            Text(
                                text = "Compiled TUN routes: ${c.includeRoutes.size} include CIDR(s), ${c.excludeRoutes.size} bypass CIDR(s) (${c.expandedPrefixes} GeoIP/ASN prefixes expanded)",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSave(draftPolicy) }) { Text("Save Redirect Rules") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

package dev.l2tunnel.android.ui

import android.content.Intent
import android.content.pm.PackageManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.l2tunnel.android.AndroidVpnProfile
import dev.l2tunnel.android.SplitTunnelMode
import dev.l2tunnel.android.StoredProfileSummary

private data class InstalledAppItem(
    val packageName: String,
    val label: String,
)

@Composable
fun ProfilesScreen(
    profiles: List<StoredProfileSummary>,
    activeProfileId: String?,
    statusBanner: String?,
    isWideLayout: Boolean,
    onSelectProfile: (String) -> Unit,
    onImportZip: () -> Unit,
    onSaveProfile: (String, AndroidVpnProfile) -> Unit,
    onDuplicateProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onSealKeystore: (String) -> Unit,
    onReplaceKeyFile: (String, String) -> Unit,
) {
    var editingSummary by remember { mutableStateOf<StoredProfileSummary?>(null) }
    var splitEditingSummary by remember { mutableStateOf<StoredProfileSummary?>(null) }
    var duplicateTargetFor by remember { mutableStateOf<String?>(null) }
    var duplicateName by remember { mutableStateOf("") }
    var deleteConfirmId by remember { mutableStateOf<String?>(null) }

    val importCard: @Composable () -> Unit = {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    text = "Profiles & Android Keystore (CL-31)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "Private keys (noise-private.key, member.pk8, admission.key, psk.key) are sealed at rest under AndroidKeyStore AES-256-GCM inside noBackupFilesDir and scrubbed from ephemeral runtime staging immediately after tunnel start.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = onImportZip) {
                        Icon(Icons.Filled.FileUpload, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Import .zip Bundle")
                    }
                }
                if (!statusBanner.isNullOrBlank()) {
                    Surface(
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                        shape = MaterialTheme.shapes.small,
                    ) {
                        Text(
                            text = statusBanner,
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(10.dp),
                        )
                    }
                }
            }
        }
    }

    val profilesList: @Composable () -> Unit = {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (profiles.isEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier.padding(20.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            text = "No profiles stored yet",
                            style = MaterialTheme.typography.titleSmall,
                        )
                        Text(
                            text = "Import a .zip archive containing client.json, common.json, noise-peer.pub, noise-private.key, member.pk8, and admission.key (plus optional android_vpn.json and psk.key).",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                profiles.forEach { summary ->
                    val isActive = summary.id == activeProfileId
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isActive) {
                                MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.45f)
                            } else {
                                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
                            },
                        ),
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier
                                        .weight(1f)
                                        .clickable { onSelectProfile(summary.id) },
                                ) {
                                    Icon(
                                        imageVector = if (isActive) Icons.Filled.CheckCircle else Icons.Filled.Key,
                                        contentDescription = null,
                                        tint = if (isActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.size(22.dp),
                                    )
                                    Spacer(Modifier.width(8.dp))
                                    Column {
                                        Text(
                                            text = summary.id + if (isActive) " (Active)" else "",
                                            style = MaterialTheme.typography.titleMedium,
                                            fontWeight = FontWeight.SemiBold,
                                        )
                                        val prof = summary.profile
                                        Text(
                                            text = if (prof != null) {
                                                "${prof.udpPeer} · ${prof.cover} · TUN ${prof.tunAddress}/${prof.tunPrefixLength}"
                                            } else {
                                                "Invalid: ${summary.validationError}"
                                            },
                                            style = MaterialTheme.typography.bodySmall,
                                            color = if (prof != null) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                                Row {
                                    IconButton(
                                        onClick = { editingSummary = summary },
                                        enabled = summary.profile != null,
                                    ) {
                                        Icon(Icons.Filled.Edit, contentDescription = "Edit profile")
                                    }
                                    IconButton(
                                        onClick = {
                                            duplicateTargetFor = summary.id
                                            duplicateName = "${summary.id}-copy"
                                        },
                                    ) {
                                        Icon(Icons.Filled.ContentCopy, contentDescription = "Duplicate profile")
                                    }
                                    IconButton(onClick = { deleteConfirmId = summary.id }) {
                                        Icon(Icons.Filled.Delete, contentDescription = "Delete profile")
                                    }
                                }
                            }

                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                AssistChip(
                                    onClick = { if (!summary.keystoreSealed) onSealKeystore(summary.id) },
                                    leadingIcon = {
                                        Icon(
                                            imageVector = if (summary.keystoreSealed) Icons.Filled.Lock else Icons.Filled.Warning,
                                            contentDescription = null,
                                            modifier = Modifier.size(16.dp),
                                        )
                                    },
                                    label = {
                                        Text(
                                            if (summary.keystoreSealed) "Keystore AES-GCM" else "Seal in Keystore",
                                        )
                                    },
                                )
                                if (summary.profile != null) {
                                    val prof = summary.profile
                                    val splitLabel = when (prof.splitTunnelMode) {
                                        SplitTunnelMode.ALL -> "Split: All"
                                        SplitTunnelMode.EXCLUDE -> "Exclude ${prof.splitTunnelApps.size}"
                                        SplitTunnelMode.INCLUDE -> "Only ${prof.splitTunnelApps.size}"
                                    }
                                    AssistChip(
                                        onClick = { splitEditingSummary = summary },
                                        leadingIcon = {
                                            Icon(Icons.Filled.Apps, contentDescription = null, modifier = Modifier.size(16.dp))
                                        },
                                        label = { Text(splitLabel) },
                                    )
                                }
                            }

                            Text(
                                text = "Peer pubkey SHA-256: ${summary.peerKeyFingerprint ?: "—"} · " +
                                    "Keys present: ${summary.presentSecrets.joinToString(", ").ifEmpty { "none" }}",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )

                            if (!isActive) {
                                FilledTonalButton(onClick = { onSelectProfile(summary.id) }) {
                                    Text("Set Active")
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (isWideLayout) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(14.dp),
                verticalAlignment = Alignment.Top,
            ) {
                Column(modifier = Modifier.weight(0.42f)) { importCard() }
                Column(modifier = Modifier.weight(0.58f)) { profilesList() }
            }
        } else {
            importCard()
            profilesList()
        }
    }

    // Typed L3 TUN Profile Editor Dialog
    editingSummary?.let { summary ->
        summary.profile?.let { prof ->
            ProfileEditorDialog(
                profileId = summary.id,
                initial = prof,
                onDismiss = { editingSummary = null },
                onSave = { updated ->
                    onSaveProfile(summary.id, updated)
                    editingSummary = null
                },
                onReplaceKeyFile = { fileName -> onReplaceKeyFile(summary.id, fileName) },
            )
        }
    }

    // Per-App Split Tunneling Dialog
    splitEditingSummary?.let { summary ->
        summary.profile?.let { prof ->
            AppSplitTunnelDialog(
                initialMode = prof.splitTunnelMode,
                initialPackages = prof.splitTunnelApps,
                onDismiss = { splitEditingSummary = null },
                onSave = { mode, pkgs ->
                    onSaveProfile(
                        summary.id,
                        prof.copy(splitTunnelMode = mode, splitTunnelApps = pkgs),
                    )
                    splitEditingSummary = null
                },
            )
        }
    }

    // Duplicate Profile Dialog
    duplicateTargetFor?.let { sourceId ->
        AlertDialog(
            onDismissRequest = { duplicateTargetFor = null },
            title = { Text("Duplicate '$sourceId'") },
            text = {
                OutlinedTextField(
                    value = duplicateName,
                    onValueChange = { duplicateName = it },
                    label = { Text("New profile name") },
                    singleLine = true,
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        onDuplicateProfile(sourceId, duplicateName)
                        duplicateTargetFor = null
                    },
                ) { Text("Duplicate") }
            },
            dismissButton = {
                TextButton(onClick = { duplicateTargetFor = null }) { Text("Cancel") }
            },
        )
    }

    // Delete Confirmation Dialog
    deleteConfirmId?.let { id ->
        AlertDialog(
            onDismissRequest = { deleteConfirmId = null },
            title = { Text("Delete profile '$id'?") },
            text = { Text("All configuration and Keystore-encrypted key files for '$id' will be securely wiped.") },
            confirmButton = {
                Button(
                    onClick = {
                        onDeleteProfile(id)
                        deleteConfirmId = null
                    },
                ) { Text("Wipe & Delete") }
            },
            dismissButton = {
                TextButton(onClick = { deleteConfirmId = null }) { Text("Cancel") }
            },
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ProfileEditorDialog(
    profileId: String,
    initial: AndroidVpnProfile,
    onDismiss: () -> Unit,
    onSave: (AndroidVpnProfile) -> Unit,
    onReplaceKeyFile: (String) -> Unit,
) {
    var udpPeer by remember { mutableStateOf(initial.udpPeer) }
    var cover by remember { mutableStateOf(initial.cover) }
    var noiseProfile by remember { mutableStateOf(initial.noiseProfile) }
    var tunMtu by remember { mutableStateOf(initial.tunMtu.toString()) }
    var pathMtu by remember { mutableStateOf(initial.pathMtu.toString()) }
    var tunAddress by remember { mutableStateOf(initial.tunAddress) }
    var tunPrefix by remember { mutableStateOf(initial.tunPrefixLength.toString()) }
    var routesText by remember {
        mutableStateOf(initial.routes.joinToString(", ") { "${it.first}/${it.second}" })
    }
    var dnsText by remember { mutableStateOf(initial.dnsServers.joinToString(", ")) }
    var tuneRepair by remember { mutableStateOf(initial.tuneRepair ?: "off,1/8,1/4") }
    var errorText by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Edit Profile: $profileId") },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = 460.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Layer: TUN (L3) — TAP/VXLAN L2 attachments are unsupported on standard Android VpnService.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value = udpPeer,
                    onValueChange = { udpPeer = it },
                    label = { Text("Server Endpoint (host:port)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text("Initial UDP Cover", style = MaterialTheme.typography.labelMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    AndroidVpnProfile.SUPPORTED_COVERS.forEach { c ->
                        FilterChip(
                            selected = cover == c,
                            onClick = { cover = c },
                            label = { Text(c) },
                        )
                    }
                }
                Text("Noise Profile", style = MaterialTheme.typography.labelMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    AndroidVpnProfile.SUPPORTED_NOISE.forEach { n ->
                        FilterChip(
                            selected = noiseProfile == n,
                            onClick = { noiseProfile = n },
                            label = { Text(n.uppercase()) },
                        )
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = tunAddress,
                        onValueChange = { tunAddress = it },
                        label = { Text("TUN IP") },
                        singleLine = true,
                        modifier = Modifier.weight(2f),
                    )
                    OutlinedTextField(
                        value = tunPrefix,
                        onValueChange = { tunPrefix = it },
                        label = { Text("Prefix") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = tunMtu,
                        onValueChange = { tunMtu = it },
                        label = { Text("TUN MTU") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = pathMtu,
                        onValueChange = { pathMtu = it },
                        label = { Text("Path MTU") },
                        singleLine = true,
                        modifier = Modifier.weight(1f),
                    )
                }
                OutlinedTextField(
                    value = routesText,
                    onValueChange = { routesText = it },
                    label = { Text("CIDR Routes (comma-separated)") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = dnsText,
                    onValueChange = { dnsText = it },
                    label = { Text("DNS Servers (optional, comma-separated)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = tuneRepair,
                    onValueChange = { tuneRepair = it },
                    label = { Text("Live Tuning FEC Catalog (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(4.dp))
                Text("Rotate / Replace Key Files (Keystore sealed)", style = MaterialTheme.typography.labelMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("noise-private.key", "noise-peer.pub", "member.pk8", "admission.key", "common.json").forEach { f ->
                        OutlinedButton(onClick = { onReplaceKeyFile(f) }) {
                            Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(14.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(f, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
                if (!errorText.isNullOrBlank()) {
                    Text(
                        text = errorText!!,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    try {
                        val parsedTunMtu = tunMtu.trim().toInt()
                        val parsedPathMtu = pathMtu.trim().toInt()
                        val parsedPrefix = tunPrefix.trim().toInt()
                        val parsedRoutes = AndroidVpnProfile.parseCidrsText(routesText)
                        val parsedDns = dnsText.split(',', ';')
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                        val updated = initial.copy(
                            udpPeer = udpPeer.trim(),
                            cover = cover,
                            noiseProfile = noiseProfile,
                            tunMtu = parsedTunMtu,
                            pathMtu = parsedPathMtu,
                            tunAddress = tunAddress.trim(),
                            tunPrefixLength = parsedPrefix,
                            routes = parsedRoutes,
                            dnsServers = parsedDns,
                            tuneRepair = tuneRepair.trim().ifEmpty { null },
                        )
                        // Validate via strict parser before saving.
                        AndroidVpnProfile.parse(initial.profileDir, updated.toClientJson(), updated.toAndroidVpnJson())
                        onSave(updated)
                    } catch (e: Exception) {
                        errorText = e.message ?: "Invalid profile settings"
                    }
                },
            ) { Text("Save") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppSplitTunnelDialog(
    initialMode: SplitTunnelMode,
    initialPackages: List<String>,
    onDismiss: () -> Unit,
    onSave: (SplitTunnelMode, List<String>) -> Unit,
) {
    val context = LocalContext.current
    val selfPkg = context.packageName
    var mode by remember { mutableStateOf(initialMode) }
    var selected by remember { mutableStateOf(initialPackages.filter { it != selfPkg }.toSet()) }
    var search by remember { mutableStateOf("") }

    val installedApps = remember {
        val pm = context.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = pm.queryIntentActivities(intent, PackageManager.MATCH_ALL)
        resolved
            .mapNotNull { info ->
                val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
                if (pkg == selfPkg) return@mapNotNull null
                val label = info.loadLabel(pm)?.toString()?.ifBlank { pkg } ?: pkg
                InstalledAppItem(pkg, label)
            }
            .distinctBy { it.packageName }
            .sortedBy { it.label.lowercase() }
    }

    val filtered = remember(installedApps, search) {
        val q = search.trim().lowercase()
        if (q.isEmpty()) installedApps else installedApps.filter {
            it.label.lowercase().contains(q) || it.packageName.lowercase().contains(q)
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Per-App Split Tunneling") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    FilterChip(
                        selected = mode == SplitTunnelMode.ALL,
                        onClick = { mode = SplitTunnelMode.ALL },
                        label = { Text("All Apps") },
                    )
                    FilterChip(
                        selected = mode == SplitTunnelMode.EXCLUDE,
                        onClick = { mode = SplitTunnelMode.EXCLUDE },
                        label = { Text("Exclude Selected") },
                    )
                    FilterChip(
                        selected = mode == SplitTunnelMode.INCLUDE,
                        onClick = { mode = SplitTunnelMode.INCLUDE },
                        label = { Text("Only Selected") },
                    )
                }
                Text(
                    text = "l2tunnel ($selfPkg) is always excluded from tun0 to prevent routing loops.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (mode != SplitTunnelMode.ALL) {
                    OutlinedTextField(
                        value = search,
                        onValueChange = { search = it },
                        label = { Text("Filter apps (${selected.size} selected)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    LazyColumn(modifier = Modifier.height(260.dp)) {
                        items(filtered, key = { it.packageName }) { app ->
                            val checked = app.packageName in selected
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        selected = if (checked) selected - app.packageName else selected + app.packageName
                                    }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = checked,
                                    onCheckedChange = { isChecked ->
                                        selected = if (isChecked) selected + app.packageName else selected - app.packageName
                                    },
                                )
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = app.label,
                                        style = MaterialTheme.typography.bodyMedium,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                    Text(
                                        text = app.packageName,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSave(mode, selected.sorted()) }) {
                Text("Save Split Rules")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

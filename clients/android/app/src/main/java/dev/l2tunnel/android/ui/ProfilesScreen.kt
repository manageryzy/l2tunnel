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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Check
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import dev.l2tunnel.android.AndroidVpnProfile
import dev.l2tunnel.android.SplitTunnelMode
import dev.l2tunnel.android.StoredProfileSummary
import java.io.File

private data class InstalledAppItem(
    val packageName: String,
    val label: String,
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ProfilesScreen(
    profiles: List<StoredProfileSummary>,
    activeProfileId: String?,
    statusBanner: String?,
    isWideLayout: Boolean,
    onSelectProfile: (String) -> Unit,
    onImportZip: () -> Unit,
    onCreateProfile: (String) -> String?,
    onGenerateKeystoreKeys: (String) -> Unit,
    onSaveHexKey: (String, String, String) -> String?,
    onSaveProfile: (String, AndroidVpnProfile) -> Unit,
    onDuplicateProfile: (String, String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    onSealKeystore: (String) -> Unit,
    onReplaceKeyFile: (String, String) -> Unit,
) {
    var editingProfileId by remember { mutableStateOf<String?>(null) }
    var splitEditingProfileId by remember { mutableStateOf<String?>(null) }
    var createDialogOpen by remember { mutableStateOf(false) }
    var newProfileName by remember { mutableStateOf("") }
    var duplicateTargetFor by remember { mutableStateOf<String?>(null) }
    var duplicateName by remember { mutableStateOf("") }
    var deleteConfirmId by remember { mutableStateOf<String?>(null) }

    val editingSummary = profiles.firstOrNull { it.id == editingProfileId }
    val splitEditingSummary = profiles.firstOrNull { it.id == splitEditingProfileId }

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
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(onClick = onImportZip) {
                        Icon(Icons.Filled.FileUpload, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Import .zip Bundle")
                    }
                    FilledTonalButton(
                        onClick = {
                            newProfileName = "profile-${profiles.size + 1}"
                            createDialogOpen = true
                        },
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text("New Profile")
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
                            text = "Import a .zip archive or tap New Profile to configure client.json, common.json, noise-peer.pub, noise-private.key, member.pk8, and admission.key.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            } else {
                profiles.forEach { summary ->
                    val isActive = summary.id == activeProfileId
                    val editable = summary.editableProfile
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
                                                "Incomplete: ${summary.validationError}"
                                            },
                                            style = MaterialTheme.typography.bodySmall,
                                            color = if (prof != null) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                                        )
                                    }
                                }
                                Row {
                                    // Always enabled so incomplete profiles can attach missing common.json/keys!
                                    IconButton(onClick = { editingProfileId = summary.id }) {
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

                            FlowRow(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                when {
                                    summary.keystoreSealed -> {
                                        AssistChip(
                                            onClick = { editingProfileId = summary.id },
                                            leadingIcon = {
                                                Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(16.dp))
                                            },
                                            label = { Text("Keystore AES-GCM") },
                                        )
                                    }
                                    summary.presentSecrets.isNotEmpty() -> {
                                        AssistChip(
                                            onClick = { onSealKeystore(summary.id) },
                                            leadingIcon = {
                                                Icon(Icons.Filled.Warning, contentDescription = null, modifier = Modifier.size(16.dp))
                                            },
                                            label = { Text("Seal in Keystore") },
                                        )
                                    }
                                    else -> {
                                        AssistChip(
                                            onClick = { onGenerateKeystoreKeys(summary.id) },
                                            leadingIcon = {
                                                Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(16.dp))
                                            },
                                            label = { Text("Generate Keystore Keys") },
                                        )
                                    }
                                }
                                if (editable != null) {
                                    val splitLabel = when (editable.splitTunnelMode) {
                                        SplitTunnelMode.ALL -> "Split: All"
                                        SplitTunnelMode.EXCLUDE -> "Exclude ${editable.splitTunnelApps.size}"
                                        SplitTunnelMode.INCLUDE -> "Only ${editable.splitTunnelApps.size}"
                                    }
                                    AssistChip(
                                        onClick = { splitEditingProfileId = summary.id },
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

    // Typed L3 TUN Profile Editor Dialog (landscape-aware, always editable even when incomplete)
    if (editingSummary != null) {
        val initial = editingSummary.editableProfile ?: defaultProfileTemplate(editingSummary.directory)
        ProfileEditorDialog(
            profileId = editingSummary.id,
            initial = initial,
            summary = editingSummary,
            isWideLayout = isWideLayout,
            onDismiss = { editingProfileId = null },
            onSave = { updated ->
                onSaveProfile(editingSummary.id, updated)
                editingProfileId = null
            },
            onGenerateKeystoreKeys = { onGenerateKeystoreKeys(editingSummary.id) },
            onSaveHexKey = { fileName, hex -> onSaveHexKey(editingSummary.id, fileName, hex) },
            onReplaceKeyFile = { fileName -> onReplaceKeyFile(editingSummary.id, fileName) },
        )
    }

    // Per-App Split Tunneling Dialog
    if (splitEditingSummary != null) {
        val prof = splitEditingSummary.editableProfile
        if (prof != null) {
            AppSplitTunnelDialog(
                initialMode = prof.splitTunnelMode,
                initialPackages = prof.splitTunnelApps,
                isWideLayout = isWideLayout,
                onDismiss = { splitEditingProfileId = null },
                onSave = { mode, pkgs ->
                    onSaveProfile(
                        splitEditingSummary.id,
                        prof.copy(splitTunnelMode = mode, splitTunnelApps = pkgs),
                    )
                    splitEditingProfileId = null
                },
            )
        }
    }

    // Create New Profile Dialog (automatically generates Keystore AES-GCM keys + default common.json)
    if (createDialogOpen) {
        AlertDialog(
            onDismissRequest = { createDialogOpen = false },
            title = { Text("New Keystore Profile") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Generates fresh Ed25519 member + X25519 Noise + admission keys sealed in Android Keystore (AES-256-GCM) and a default L3 common.json plan.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    OutlinedTextField(
                        value = newProfileName,
                        onValueChange = { newProfileName = it },
                        label = { Text("Profile name") },
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val createdId = onCreateProfile(newProfileName)
                        createDialogOpen = false
                        if (createdId != null) {
                            editingProfileId = createdId
                        }
                    },
                ) { Text("Create & Open Editor") }
            },
            dismissButton = {
                TextButton(onClick = { createDialogOpen = false }) { Text("Cancel") }
            },
        )
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

private fun defaultProfileTemplate(dir: File): AndroidVpnProfile =
    AndroidVpnProfile(
        profileDir = dir,
        cover = "quic-like",
        udpBind = "0.0.0.0:0",
        udpPeer = "192.168.1.1:24461",
        pathMtu = 1500,
        tunMtu = 1500,
        noiseProfile = "ik",
        handshakeSeconds = 30,
        tuneRepair = "off,1/8,1/4",
        tunAddress = AndroidVpnProfile.DEFAULT_TUN_ADDRESS,
        tunPrefixLength = AndroidVpnProfile.DEFAULT_TUN_PREFIX,
        routes = listOf("0.0.0.0" to 0),
        dnsServers = emptyList(),
    )

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ProfileEditorDialog(
    profileId: String,
    initial: AndroidVpnProfile,
    summary: StoredProfileSummary,
    isWideLayout: Boolean,
    onDismiss: () -> Unit,
    onSave: (AndroidVpnProfile) -> Unit,
    onGenerateKeystoreKeys: () -> Unit,
    onSaveHexKey: (String, String) -> String?,
    onReplaceKeyFile: (String) -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val presentFiles = summary.presentFiles
    var udpPeer by remember(profileId) { mutableStateOf(initial.udpPeer) }
    var cover by remember(profileId) { mutableStateOf(initial.cover) }
    var noiseProfile by remember(profileId) { mutableStateOf(initial.noiseProfile) }
    var tunMtu by remember(profileId) { mutableStateOf(initial.tunMtu.toString()) }
    var pathMtu by remember(profileId) { mutableStateOf(initial.pathMtu.toString()) }
    var tunAddress by remember(profileId) { mutableStateOf(initial.tunAddress) }
    var tunPrefix by remember(profileId) { mutableStateOf(initial.tunPrefixLength.toString()) }
    var routesText by remember(profileId) {
        mutableStateOf(initial.routes.joinToString(", ") { "${it.first}/${it.second}" })
    }
    var dnsText by remember(profileId) { mutableStateOf(initial.dnsServers.joinToString(", ")) }
    var tuneRepair by remember(profileId) { mutableStateOf(initial.tuneRepair ?: "off,1/8,1/4") }
    var peerPubHex by remember(profileId) { mutableStateOf("") }
    var admissionHex by remember(profileId) { mutableStateOf("") }
    var copiedNotice by remember { mutableStateOf<String?>(null) }
    var errorText by remember { mutableStateOf<String?>(null) }

    val leftFields: @Composable () -> Unit = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
        }
    }

    val rightFields: @Composable () -> Unit = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = routesText,
                onValueChange = { routesText = it },
                label = { Text("CIDR Routes (comma-separated)") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = dnsText,
                onValueChange = { dnsText = it },
                label = { Text("DNS Servers (optional)") },
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
            Text("Keystore Keys & Plan Files", style = MaterialTheme.typography.labelMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilledTonalButton(onClick = onGenerateKeystoreKeys) {
                    Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Generate Keys in Keystore", style = MaterialTheme.typography.labelMedium)
                }
            }
            if (summary.clientNoisePubHex != null || summary.clientMemberPubHex != null) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    summary.clientNoisePubHex?.let { hex ->
                        AssistChip(
                            onClick = {
                                clipboard.setText(AnnotatedString(hex))
                                copiedNotice = "Copied client Noise pubkey (${hex.take(12)}…)"
                            },
                            leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp)) },
                            label = { Text("Copy Noise Pub: ${hex.take(10)}…", fontFamily = FontFamily.Monospace) },
                        )
                    }
                    summary.clientMemberPubHex?.let { hex ->
                        AssistChip(
                            onClick = {
                                clipboard.setText(AnnotatedString(hex))
                                copiedNotice = "Copied client Member pubkey (${hex.take(12)}…)"
                            },
                            leadingIcon = { Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(14.dp)) },
                            label = { Text("Copy Member Pub: ${hex.take(10)}…", fontFamily = FontFamily.Monospace) },
                        )
                    }
                }
            }
            if (!copiedNotice.isNullOrBlank()) {
                Text(
                    text = copiedNotice!!,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            OutlinedTextField(
                value = peerPubHex,
                onValueChange = { peerPubHex = it },
                label = {
                    Text(
                        if ("noise-peer.pub" in presentFiles) {
                            "Server Noise Pubkey (64 hex · saved ✓)"
                        } else {
                            "Server Noise Pubkey (paste 64 hex)"
                        },
                    )
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = admissionHex,
                onValueChange = { admissionHex = it },
                label = {
                    Text(
                        if ("admission.key" in presentFiles) {
                            "Admission Secret (64 hex · Keystore sealed ✓)"
                        } else {
                            "Admission Secret (paste 64 hex)"
                        },
                    )
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                listOf("common.json", "noise-peer.pub", "noise-private.key", "member.pk8", "admission.key").forEach { f ->
                    val present = f in presentFiles
                    OutlinedButton(onClick = { onReplaceKeyFile(f) }) {
                        Icon(
                            imageVector = if (present) Icons.Filled.Check else Icons.Filled.Add,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(f, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth(if (isWideLayout) 0.86f else 0.94f)
            .widthIn(max = 840.dp),
        title = { Text("Edit Profile: $profileId") },
        text = {
            Column(
                modifier = Modifier
                    .heightIn(max = if (isWideLayout) 380.dp else 480.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Layer: TUN (L3) — TAP/VXLAN L2 attachments are unsupported on standard Android VpnService.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (isWideLayout) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(14.dp),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Column(modifier = Modifier.weight(1f)) { leftFields() }
                        Column(modifier = Modifier.weight(1f)) { rightFields() }
                    }
                } else {
                    leftFields()
                    rightFields()
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
                        AndroidVpnProfile.parse(initial.profileDir, updated.toClientJson(), updated.toAndroidVpnJson())
                        if (peerPubHex.isNotBlank()) {
                            val err = onSaveHexKey("noise-peer.pub", peerPubHex)
                            if (err != null) {
                                errorText = "Server Noise Pubkey: $err"
                                return@Button
                            }
                        }
                        if (admissionHex.isNotBlank()) {
                            val err = onSaveHexKey("admission.key", admissionHex)
                            if (err != null) {
                                errorText = "Admission Secret: $err"
                                return@Button
                            }
                        }
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
    isWideLayout: Boolean,
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
        properties = DialogProperties(usePlatformDefaultWidth = false),
        modifier = Modifier
            .fillMaxWidth(if (isWideLayout) 0.72f else 0.94f)
            .widthIn(max = 680.dp),
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
                    LazyColumn(modifier = Modifier.height(if (isWideLayout) 220.dp else 260.dp)) {
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

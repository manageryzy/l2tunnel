package dev.l2tunnel.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Assessment
import androidx.compose.material.icons.filled.FolderShared
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.l2tunnel.android.ui.ConnectionScreen
import dev.l2tunnel.android.ui.L2TunnelTheme
import dev.l2tunnel.android.ui.OverviewScreen
import dev.l2tunnel.android.ui.ProfilesScreen
import dev.l2tunnel.android.ui.StatsScreen
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Jetpack Compose + Material 3 (Material You) Android client host (CL-28..CL-31).
 *
 * Hosts 4 bottom-navigation tabs mirroring the desktop GUI (Overview, Connection,
 * Profiles & Keys, Stats & Logs) while delegating all tunnel lifecycle, FD protection,
 * Keystore secret materialization, and Local API v5 operations to [L2TunnelVpnService].
 */
class MainActivity : ComponentActivity() {
    private lateinit var profileStore: ProfileStore

    private var profilesState by mutableStateOf<List<StoredProfileSummary>>(emptyList())
    private var activeProfileIdState by mutableStateOf<String?>(null)
    private var overviewErrorState by mutableStateOf<String?>(null)
    private var profileBannerState by mutableStateOf<String?>(null)
    private var pendingKeyTarget: Pair<String, String>? = null
    private var pendingDiagnosticsRedact: Boolean = true

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnServiceForActiveProfile()
        } else {
            overviewErrorState = "VPN authorization declined by user."
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        // Proceed regardless; foreground notification is still posted by VpnService.
    }

    private val importZipLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        if (uri != null) handleZipImport(uri)
    }

    private val importSingleFileLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri: Uri? ->
        val target = pendingKeyTarget
        pendingKeyTarget = null
        if (uri != null && target != null) {
            handleSingleKeyImport(target.first, target.second, uri)
        }
    }

    private val exportDiagnosticsLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri: Uri? ->
        if (uri != null) handleDiagnosticsExport(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        profileStore = ProfileStore(
            profilesRoot = File(noBackupFilesDir, "profiles"),
            legacyDefaultDir = File(filesDir, "profiles/default"),
        )
        reloadProfiles()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            L2TunnelTheme {
                L2TunnelAppRoot()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        reloadProfiles()
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun L2TunnelAppRoot() {
        val vpnState by L2TunnelVpnService.uiState.collectAsStateWithLifecycle()
        var selectedTab by rememberSaveable { mutableIntStateOf(0) }
        val activeSummary = profilesState.firstOrNull { it.id == activeProfileIdState }

        val tabs = listOf(
            Triple("Overview", Icons.Filled.Home, 0),
            Triple("Connection", Icons.Filled.Tune, 1),
            Triple("Profiles", Icons.Filled.FolderShared, 2),
            Triple("Stats", Icons.Filled.Assessment, 3),
        )

        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            text = when (selectedTab) {
                                0 -> "l2tunnel"
                                1 -> "Connection"
                                2 -> "Profiles & Keys"
                                else -> "Stats & Logs"
                            },
                        )
                    },
                )
            },
            bottomBar = {
                NavigationBar {
                    tabs.forEach { (label, icon, index) ->
                        NavigationBarItem(
                            selected = selectedTab == index,
                            onClick = { selectedTab = index },
                            icon = { Icon(icon, contentDescription = label) },
                            label = { Text(label) },
                        )
                    }
                }
            },
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                when (selectedTab) {
                    0 -> OverviewScreen(
                        state = vpnState,
                        profiles = profilesState,
                        activeProfile = activeSummary,
                        inlineError = overviewErrorState,
                        onSelectProfile = { id -> selectProfile(id) },
                        onConnect = { requestVpnAndStart() },
                        onReconnect = { sendServiceAction(L2TunnelVpnService.ACTION_RECONNECT) },
                        onDisconnect = { sendServiceAction(L2TunnelVpnService.ACTION_STOP) },
                        onOpenProfilesTab = { selectedTab = 2 },
                    )
                    1 -> ConnectionScreen(
                        state = vpnState,
                        onSwitchCover = { target ->
                            startService(
                                Intent(this@MainActivity, L2TunnelVpnService::class.java)
                                    .setAction(L2TunnelVpnService.ACTION_SWITCH_COVER)
                                    .putExtra(L2TunnelVpnService.EXTRA_COVER, target),
                            )
                        },
                        onTuningSwitch = { setting ->
                            startService(
                                Intent(this@MainActivity, L2TunnelVpnService::class.java)
                                    .setAction(L2TunnelVpnService.ACTION_TUNE_SWITCH)
                                    .putExtra(L2TunnelVpnService.EXTRA_TUNE_REPAIR, setting.repair)
                                    .putExtra(L2TunnelVpnService.EXTRA_TUNE_DEV_MTU, setting.deviceMtu)
                                    .putExtra(L2TunnelVpnService.EXTRA_TUNE_PATH_MTU, setting.pathMtu),
                            )
                        },
                        onRateBudgetSet = { sendBps, recvBps ->
                            startService(
                                Intent(this@MainActivity, L2TunnelVpnService::class.java)
                                    .setAction(L2TunnelVpnService.ACTION_RATE_BUDGET)
                                    .putExtra(L2TunnelVpnService.EXTRA_SEND_RATE_BPS, sendBps)
                                    .putExtra(L2TunnelVpnService.EXTRA_RECV_RATE_BPS, recvBps),
                            )
                        },
                        onTestPing = { count ->
                            startService(
                                Intent(this@MainActivity, L2TunnelVpnService::class.java)
                                    .setAction(L2TunnelVpnService.ACTION_TEST_PING)
                                    .putExtra(L2TunnelVpnService.EXTRA_TEST_COUNT, count),
                            )
                        },
                        onTestSpeed = { dir, streams, durationMs ->
                            startService(
                                Intent(this@MainActivity, L2TunnelVpnService::class.java)
                                    .setAction(L2TunnelVpnService.ACTION_TEST_SPEED)
                                    .putExtra(L2TunnelVpnService.EXTRA_TEST_DIRECTION, dir)
                                    .putExtra(L2TunnelVpnService.EXTRA_TEST_STREAMS, streams)
                                    .putExtra(L2TunnelVpnService.EXTRA_TEST_DURATION_MS, durationMs),
                            )
                        },
                        onTestCancel = { id ->
                            startService(
                                Intent(this@MainActivity, L2TunnelVpnService::class.java)
                                    .setAction(L2TunnelVpnService.ACTION_TEST_CANCEL)
                                    .putExtra(L2TunnelVpnService.EXTRA_TEST_ID, id),
                            )
                        },
                    )
                    2 -> ProfilesScreen(
                        profiles = profilesState,
                        activeProfileId = activeProfileIdState,
                        statusBanner = profileBannerState,
                        onSelectProfile = { id -> selectProfile(id) },
                        onImportZip = {
                            importZipLauncher.launch(arrayOf("application/zip", "application/octet-stream", "*/*"))
                        },
                        onSaveProfile = { id, updated ->
                            try {
                                profileStore.saveEditedProfile(id, updated)
                                reloadProfiles()
                                profileBannerState = "Saved profile '$id'."
                            } catch (e: Exception) {
                                profileBannerState = "Save failed: ${e.message}"
                            }
                        },
                        onDuplicateProfile = { src, dst ->
                            try {
                                val dup = profileStore.duplicateProfile(src, dst)
                                reloadProfiles()
                                profileBannerState = "Duplicated '$src' -> '${dup.id}' (Keystore sealed)."
                            } catch (e: Exception) {
                                profileBannerState = "Duplicate failed: ${e.message}"
                            }
                        },
                        onDeleteProfile = { id ->
                            profileStore.deleteProfile(id)
                            reloadProfiles()
                            profileBannerState = "Wiped and deleted profile '$id'."
                        },
                        onSealKeystore = { id ->
                            try {
                                profileStore.sealProfileWithKeystore(id)
                                reloadProfiles()
                                profileBannerState = "Sealed '$id' private keys with Android Keystore AES-256-GCM."
                            } catch (e: Exception) {
                                profileBannerState = "Keystore seal failed: ${e.message}"
                            }
                        },
                        onReplaceKeyFile = { id, fileName ->
                            pendingKeyTarget = id to fileName
                            importSingleFileLauncher.launch(arrayOf("*/*"))
                        },
                    )
                    else -> StatsScreen(
                        state = vpnState,
                        onExportDiagnostics = { redact ->
                            pendingDiagnosticsRedact = redact
                            val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                            exportDiagnosticsLauncher.launch("l2tunnel-diagnostics-$ts.json")
                        },
                    )
                }
            }
        }
    }

    private fun reloadProfiles() {
        profilesState = profileStore.listProfiles()
        activeProfileIdState = profileStore.activeProfileId()
    }

    private fun selectProfile(id: String) {
        try {
            profileStore.setActiveProfile(id)
            activeProfileIdState = id
            overviewErrorState = null
        } catch (e: Exception) {
            profileBannerState = "Could not select '$id': ${e.message}"
        }
    }

    private fun requestVpnAndStart() {
        reloadProfiles()
        val activeId = activeProfileIdState
        val activeSummary = profilesState.firstOrNull { it.id == activeId }
        if (activeSummary == null || !activeSummary.isValid) {
            overviewErrorState = activeSummary?.validationError
                ?: "No profile installed. Import a .zip profile bundle in Profiles & Keys."
            return
        }
        overviewErrorState = null
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnServiceForActiveProfile()
        }
    }

    private fun startVpnServiceForActiveProfile() {
        val activeId = activeProfileIdState ?: return
        val dir = profileStore.profileDir(activeId)
        val intent = Intent(this, L2TunnelVpnService::class.java)
            .setAction(L2TunnelVpnService.ACTION_START)
            .putExtra(L2TunnelVpnService.EXTRA_PROFILE_DIR, dir.absolutePath)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun sendServiceAction(action: String) {
        val intent = Intent(this, L2TunnelVpnService::class.java).setAction(action)
        startService(intent)
    }

    private fun handleZipImport(uri: Uri) {
        try {
            val baseName = resolveDisplayName(uri)
                ?.substringBeforeLast('.')
                ?.ifBlank { "imported" }
                ?: "imported"
            val stream = contentResolver.openInputStream(uri)
                ?: throw IllegalStateException("Cannot open selected file")
            stream.use { input ->
                val imported = profileStore.importZipBundle(baseName, input)
                reloadProfiles()
                overviewErrorState = null
                profileBannerState = "Imported '${imported.id}' and sealed private keys with Android Keystore."
            }
        } catch (e: Exception) {
            profileBannerState = "Import failed: ${e.message}"
        }
    }

    private fun handleSingleKeyImport(profileId: String, fileName: String, uri: Uri) {
        try {
            val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw IllegalStateException("Cannot open selected key file")
            try {
                profileStore.saveCredentialFile(profileId, fileName, bytes)
            } finally {
                bytes.fill(0)
            }
            reloadProfiles()
            profileBannerState = "Updated '$fileName' in profile '$profileId'."
        } catch (e: Exception) {
            profileBannerState = "Key update failed: ${e.message}"
        }
    }

    private fun handleDiagnosticsExport(uri: Uri) {
        try {
            val active = profilesState.firstOrNull { it.id == activeProfileIdState }
            val version = try {
                packageManager.getPackageInfo(packageName, 0).versionName ?: "0.2.0"
            } catch (_: Exception) {
                "0.2.0"
            }
            val json = DiagnosticsExporter.buildReportJson(
                appVersion = version,
                state = L2TunnelVpnService.uiState.value,
                activeProfile = active,
                redactEndpoints = pendingDiagnosticsRedact,
            )
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(json.toByteArray(Charsets.UTF_8))
                out.flush()
            }
            profileBannerState = "Exported redacted diagnostics JSON."
        } catch (e: Exception) {
            profileBannerState = "Diagnostics export failed: ${e.message}"
        }
    }

    private fun resolveDisplayName(uri: Uri): String? {
        return try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        } catch (_: Exception) {
            null
        }
    }
}

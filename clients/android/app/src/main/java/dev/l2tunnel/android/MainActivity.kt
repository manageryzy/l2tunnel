package dev.l2tunnel.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import java.io.File

/**
 * Minimal Material 3 connect/status screen for the core Android VpnService port (CL-28..CL-30).
 *
 * Handles `VpnService.prepare()`, Android 13+ notification permission, Local API v5 live status
 * display, Reconnect/Disconnect controls, and live make-before-break UDP cover switching.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var statusHeadline: TextView
    private lateinit var statusDetails: TextView
    private lateinit var profileHint: TextView
    private lateinit var connectButton: Button
    private lateinit var reconnectButton: Button
    private lateinit var disconnectButton: Button
    private lateinit var switchQuicButton: Button
    private lateinit var switchMediaButton: Button
    private lateinit var switchTlsButton: Button

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            statusHeadline.text = "VPN authorization declined"
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {
        // Proceed regardless; foreground notification is still posted by VpnService.
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
        }

        val title = TextView(this).apply {
            text = getString(R.string.app_name)
            textSize = 24f
        }
        statusHeadline = TextView(this).apply {
            text = "Disconnected"
            textSize = 18f
            setPadding(0, pad / 2, 0, pad / 4)
        }
        statusDetails = TextView(this).apply {
            textSize = 14f
            setPadding(0, 0, 0, pad)
        }
        profileHint = TextView(this).apply {
            textSize = 12f
            setPadding(0, 0, 0, pad)
        }

        connectButton = Button(this).apply {
            text = getString(R.string.action_connect)
            setOnClickListener { requestVpnAndStart() }
        }
        reconnectButton = Button(this).apply {
            text = getString(R.string.action_reconnect)
            setOnClickListener { sendServiceAction(L2TunnelVpnService.ACTION_RECONNECT) }
        }
        disconnectButton = Button(this).apply {
            text = getString(R.string.action_disconnect)
            setOnClickListener { sendServiceAction(L2TunnelVpnService.ACTION_STOP) }
        }

        val coverLabel = TextView(this).apply {
            text = "Live UDP cover switch (make-before-break)"
            textSize = 14f
            setPadding(0, pad, 0, pad / 4)
        }
        val coverRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        switchQuicButton = Button(this).apply {
            text = getString(R.string.action_switch_quic)
            setOnClickListener { switchCover("quic-like") }
        }
        switchMediaButton = Button(this).apply {
            text = getString(R.string.action_switch_media)
            setOnClickListener { switchCover("media-like") }
        }
        switchTlsButton = Button(this).apply {
            text = getString(R.string.action_switch_tls)
            setOnClickListener { switchCover("tls-like") }
        }
        coverRow.addView(switchQuicButton)
        coverRow.addView(switchMediaButton)
        coverRow.addView(switchTlsButton)

        root.addView(title)
        root.addView(statusHeadline)
        root.addView(statusDetails)
        root.addView(profileHint)
        root.addView(connectButton)
        root.addView(reconnectButton)
        root.addView(disconnectButton)
        root.addView(coverLabel)
        root.addView(coverRow)

        val scroll = ScrollView(this).apply { addView(root) }
        setContentView(scroll)

        refreshProfileHint()

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                L2TunnelVpnService.uiState.collect { state -> render(state) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshProfileHint()
    }

    private fun defaultProfileDir(): File = File(filesDir, "profiles/default")

    private fun refreshProfileHint() {
        val dir = defaultProfileDir()
        profileHint.text = try {
            val profile = AndroidVpnProfile.loadFromDirectory(dir)
            "Profile: ${dir.name} · TUN MTU ${profile.tunMtu} · peer ${profile.udpPeer} · cover ${profile.cover}"
        } catch (e: Exception) {
            "Profile directory: ${dir.absolutePath}\nStatus: ${e.message}"
        }
    }

    private fun requestVpnAndStart() {
        val dir = defaultProfileDir()
        try {
            AndroidVpnProfile.loadFromDirectory(dir)
        } catch (e: Exception) {
            refreshProfileHint()
            statusHeadline.text = "Profile required"
            statusDetails.text = "Cannot connect: ${e.message}\nPlace client.json, common.json, and key files in ${dir.absolutePath}."
            return
        }
        refreshProfileHint()
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, L2TunnelVpnService::class.java)
            .setAction(L2TunnelVpnService.ACTION_START)
            .putExtra(L2TunnelVpnService.EXTRA_PROFILE_DIR, defaultProfileDir().absolutePath)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun sendServiceAction(action: String) {
        val intent = Intent(this, L2TunnelVpnService::class.java).setAction(action)
        startService(intent)
    }

    private fun switchCover(target: String) {
        val intent = Intent(this, L2TunnelVpnService::class.java)
            .setAction(L2TunnelVpnService.ACTION_SWITCH_COVER)
            .putExtra(L2TunnelVpnService.EXTRA_COVER, target)
        startService(intent)
    }

    private fun render(state: VpnUiState) {
        statusHeadline.text = state.headline
        val rttText = state.rttMicros?.let { String.format("%.1f ms", it / 1000.0) } ?: "—"
        statusDetails.text = buildString {
            appendLine("Phase: ${state.phase}")
            appendLine("Peer: ${state.peer ?: "—"}")
            appendLine("UDP cover: ${state.cover ?: "—"}")
            appendLine("RTT: $rttText")
            appendLine("Wire TX: ${formatBytes(state.wireSentBytes)} · RX pkts: ${state.wireReceivedPackets}")
            if (!state.detail.isNullOrBlank()) {
                append("Detail: ${state.detail}")
            }
        }
        connectButton.isEnabled = !state.running
        reconnectButton.isEnabled = state.running
        disconnectButton.isEnabled = state.running
        val connected = state.running && state.phase == "connected"
        switchQuicButton.isEnabled = connected && state.cover != "quic-like"
        switchMediaButton.isEnabled = connected && state.cover != "media-like"
        switchTlsButton.isEnabled = connected && state.cover != "tls-like"
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1_000_000_000L -> String.format("%.2f GB", bytes / 1e9)
        bytes >= 1_000_000L -> String.format("%.2f MB", bytes / 1e6)
        bytes >= 1_000L -> String.format("%.1f KB", bytes / 1e3)
        else -> "$bytes B"
    }
}

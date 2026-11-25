package dev.l2tunnel.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process as AndroidProcess
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class VpnUiState(
    val running: Boolean = false,
    val phase: String = "disconnected",
    val headline: String = "Disconnected",
    val detail: String? = null,
    val peer: String? = null,
    val cover: String? = null,
    val wireSentBytes: Long = 0L,
    val wireReceivedPackets: Long = 0L,
    val rttMicros: Long? = null,
    val profileName: String? = null,
)

/**
 * Android `VpnService` owning the single tunnel lifecycle (CL-28, CL-29, CL-30).
 *
 * - Runs as a foreground service with a required notification channel and explicit `onRevoke()` cleanup.
 * - Launches the app-private Rust `libl2tunnel_android_service.so` binary, brokers `VpnService.protect()`
 *   and `VpnService.Builder.establish()` over an UID-verified abstract Unix socket (`FdBrokerServer`),
 *   and polls/controls the session via Local API v5 (`LocalApiV5Client`).
 * - Handles default-network changes (`ConnectivityManager.NetworkCallback`) through the debounced,
 *   battery-aware `NetworkChangeCoordinator`.
 */
class L2TunnelVpnService : VpnService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val active = AtomicBoolean(false)
    private val networkCoordinator = NetworkChangeCoordinator()

    private var broker: FdBrokerServer? = null
    private var childProcess: Process? = null
    private var apiClient: LocalApiV5Client? = null
    private var apiSocketFile: File? = null
    private var pollJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var activeProfile: AndroidVpnProfile? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel("Disconnected")
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                triggerReconnect("User reconnect")
                return START_STICKY
            }
            ACTION_SWITCH_COVER -> {
                val target = intent.getStringExtra(EXTRA_COVER) ?: return START_STICKY
                triggerCarrierSwitch(target)
                return START_STICKY
            }
            ACTION_START, null -> {
                val dirPath = intent?.getStringExtra(EXTRA_PROFILE_DIR)
                    ?: File(filesDir, "profiles/default").absolutePath
                startTunnel(File(dirPath))
                return START_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by system; tearing down immediately")
        stopTunnel("VPN permission revoked")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel("Stopped")
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startTunnel(profileDir: File) {
        if (!active.compareAndSet(false, true)) {
            Log.i(TAG, "Ignoring duplicate start request while tunnel is active")
            return
        }
        val profile = try {
            AndroidVpnProfile.loadFromDirectory(profileDir)
        } catch (e: Exception) {
            active.set(false)
            publishState(
                VpnUiState(
                    running = false,
                    phase = "failed",
                    headline = "Invalid profile",
                    detail = e.message,
                    profileName = profileDir.name,
                ),
            )
            stopSelf()
            return
        }
        activeProfile = profile
        startForegroundServiceNotification("Connecting to ${profile.udpPeer}…")
        publishState(
            VpnUiState(
                running = true,
                phase = "authenticating",
                headline = "Connecting…",
                peer = profile.udpPeer,
                cover = profile.cover,
                profileName = profileDir.name,
            ),
        )

        val runDir = File(filesDir, "run").apply {
            mkdirs()
            setReadable(false, false)
            setWritable(false, false)
            setExecutable(false, false)
            setReadable(true, true)
            setWritable(true, true)
            setExecutable(true, true)
        }
        val sockFile = File(runDir, "service.sock")
        if (sockFile.exists()) {
            sockFile.delete()
        }
        apiSocketFile = sockFile
        apiClient = LocalApiV5Client(sockFile)

        val brokerName = "l2tunnel-vpn-${AndroidProcess.myPid()}-${BROKER_SEQ.incrementAndGet()}"
        val fdBroker = FdBrokerServer(
            abstractName = brokerName,
            protectFd = { rawFd -> protect(rawFd) },
            establishTun = { buildTunInterface(profile) },
            onReady = {
                updateNotification("Connected · ${profile.udpPeer}")
            },
        )
        broker = fdBroker
        fdBroker.start()

        val binary = File(applicationInfo.nativeLibraryDir, NATIVE_BINARY_NAME)
        if (!binary.isFile || !binary.canExecute()) {
            stopTunnel("Missing native binary ${binary.name}")
            return
        }

        try {
            val proc = ProcessBuilder(
                binary.absolutePath,
                profile.profileDir.absolutePath,
                sockFile.absolutePath,
                brokerName,
            )
                .redirectErrorStream(true)
                .start()
            childProcess = proc
            registerNetworkCallback()
            startSupervisionLoops(proc, profile)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start Rust Android service: ${e.message}")
            stopTunnel("Service launch failed: ${e.message}")
        }
    }

    private fun buildTunInterface(profile: AndroidVpnProfile): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("l2tunnel-${profile.profileDir.name}")
            .setMtu(profile.tunMtu)
            .addAddress(profile.tunAddress, profile.tunPrefixLength)
        for ((dest, prefix) in profile.routes) {
            builder.addRoute(dest, prefix)
        }
        for (dns in profile.dnsServers) {
            builder.addDnsServer(dns)
        }
        // Defense-in-depth alongside explicit VpnService.protect() on every outer socket.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }
        return builder.establish()
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        networkCoordinator.reset()
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (!active.get()) return
                if (networkCoordinator.onNetworkAvailable(network.networkHandle, SystemClock.elapsedRealtime())) {
                    Log.i(TAG, "Default network changed; scheduling bounded Local API v5 reconnect")
                    triggerReconnect("Network transition")
                }
            }

            override fun onLost(network: Network) {
                networkCoordinator.onNetworkLost(network.networkHandle)
            }
        }
        networkCallback = cb
        try {
            cm.registerNetworkCallback(request, cb)
        } catch (e: Exception) {
            Log.w(TAG, "Could not register NetworkCallback: ${e.message}")
        }
    }

    private fun startSupervisionLoops(proc: Process, profile: AndroidVpnProfile) {
        pollJob?.cancel()
        pollJob = serviceScope.launch {
            launch {
                val exit = proc.waitFor()
                if (active.get()) {
                    Log.w(TAG, "Rust Android service exited unexpectedly (code=$exit)")
                    stopTunnel("Service exited (code $exit)")
                }
            }
            while (isActive && active.get()) {
                val client = apiClient
                if (client != null && apiSocketFile?.exists() == true) {
                    try {
                        val st = client.status()
                        val m = try { client.metrics() } catch (_: Exception) { null }
                        val c = try { client.carrierShow() } catch (_: Exception) { null }
                        val headline = formatHeadline(st)
                        val effectiveCover = c?.currentCover ?: st.cover ?: profile.cover
                        publishState(
                            VpnUiState(
                                running = true,
                                phase = st.phase,
                                headline = headline,
                                detail = st.terminalReason,
                                peer = st.peer ?: profile.udpPeer,
                                cover = effectiveCover,
                                wireSentBytes = m?.wireSentBytes ?: 0L,
                                wireReceivedPackets = m?.wireReceivedPackets ?: 0L,
                                rttMicros = m?.rttMicros,
                                profileName = profile.profileDir.name,
                            ),
                        )
                        updateNotification("$headline · $effectiveCover")
                    } catch (_: Exception) {
                        // Socket may still be initializing during first handshake turn.
                    }
                }
                delay(1500L)
            }
        }
    }

    private fun triggerReconnect(reason: String) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                client.reconnect()
                Log.i(TAG, "Submitted Local API v5 reconnect ($reason)")
            } catch (e: Exception) {
                Log.w(TAG, "Reconnect request failed ($reason): ${e.message}")
            }
        }
    }

    private fun triggerCarrierSwitch(target: String) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val res = client.carrierSwitch(target)
                Log.i(TAG, "Carrier switch -> $target result=${res?.currentCover}")
            } catch (e: Exception) {
                Log.w(TAG, "Carrier switch to $target failed: ${e.message}")
            }
        }
    }

    private fun stopTunnel(reason: String) {
        val wasActive = active.getAndSet(false)
        pollJob?.cancel()
        pollJob = null

        networkCallback?.let { cb ->
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        networkCoordinator.reset()

        // Closing the FD broker closes the 'M' monitor socket and the owned TUN FD,
        // signaling l2tunnel-android-service to shut down cleanly with zero leaked FDs.
        try {
            broker?.close()
        } catch (_: Exception) {
        }
        broker = null

        childProcess?.let { proc ->
            try {
                if (!proc.waitFor(1500L, TimeUnit.MILLISECONDS)) {
                    proc.destroy()
                    if (!proc.waitFor(500L, TimeUnit.MILLISECONDS)) {
                        proc.destroyForcibly()
                    }
                }
            } catch (_: Exception) {
                proc.destroyForcibly()
            }
        }
        childProcess = null

        apiSocketFile?.let { file ->
            if (file.exists()) file.delete()
        }
        apiSocketFile = null
        apiClient = null

        if (wasActive || _uiState.value.running) {
            publishState(
                VpnUiState(
                    running = false,
                    phase = "disconnected",
                    headline = reason,
                    profileName = activeProfile?.profileDir?.name,
                ),
            )
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun formatHeadline(st: ServiceStatusSnapshot): String {
        val rec = st.recovery
        if (rec != null && rec.active) {
            return "Reconnecting (${rec.attempt}/${rec.maxAttempts})…"
        }
        return when (st.phase) {
            "connected" -> "Connected"
            "authenticating", "preparing" -> "Connecting…"
            "stopping" -> "Disconnecting…"
            "failed" -> when (st.terminalReason) {
                "lease_expired" -> "Session lease expired"
                "counter_exhausted" -> "Key counter limit reached"
                "peer_timeout" -> "Peer unreachable"
                "recovery_exhausted" -> "Reconnect attempts exhausted"
                else -> "Connection failed"
            }
            else -> "Disconnected"
        }
    }

    private fun ensureNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.vpn_channel_desc)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, L2TunnelVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.action_disconnect), stopIntent)
            .build()
    }

    private fun startForegroundServiceNotification(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun publishState(state: VpnUiState) {
        _uiState.value = state
    }

    companion object {
        private const val TAG = "L2TunnelVpnService"
        private const val CHANNEL_ID = "l2tunnel_vpn_status"
        private const val NOTIFICATION_ID = 1001
        private const val NATIVE_BINARY_NAME = "libl2tunnel_android_service.so"
        private val BROKER_SEQ = AtomicLong(0L)

        const val ACTION_START = "dev.l2tunnel.android.action.START"
        const val ACTION_STOP = "dev.l2tunnel.android.action.STOP"
        const val ACTION_RECONNECT = "dev.l2tunnel.android.action.RECONNECT"
        const val ACTION_SWITCH_COVER = "dev.l2tunnel.android.action.SWITCH_COVER"
        const val EXTRA_PROFILE_DIR = "profile_dir"
        const val EXTRA_COVER = "cover"

        private val _uiState = MutableStateFlow(VpnUiState())
        val uiState: StateFlow<VpnUiState> = _uiState.asStateFlow()
    }
}

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
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** One bounded chart sample for the Overview/Stats live throughput & RTT plots. */
data class TelemetrySample(
    val timestampMs: Long,
    val txBytesPerSec: Float,
    val rxPacketsPerSec: Float,
    val rttMs: Float?,
)

/** One bounded redacted event entry for the Stats & Logs screen. */
data class UiEventEntry(
    val timestampMs: Long,
    val source: String,
    val message: String,
)

data class VpnUiState(
    val running: Boolean = false,
    val phase: String = "disconnected",
    val headline: String = "Disconnected",
    val detail: String? = null,
    val peer: String? = null,
    val cover: String? = null,
    val carrierSwitches: Long = 0L,
    val wireSentBytes: Long = 0L,
    val wireSentPackets: Long = 0L,
    val wireReceivedPackets: Long = 0L,
    val wireSendDrops: Long = 0L,
    val wireReceiveErrors: Long = 0L,
    val wireRejectedPackets: Long = 0L,
    val wireReplayRejections: Long = 0L,
    val nativeReadPackets: Long = 0L,
    val nativeWrittenPackets: Long = 0L,
    val nativeBackpressureDrops: Long = 0L,
    val txBytesPerSec: Float = 0f,
    val rxPacketsPerSec: Float = 0f,
    val rttMicros: Long? = null,
    val sendRateBytesPerSec: Long? = null,
    val receiveRateBytesPerSec: Long? = null,
    val profileName: String? = null,
    val recoveryAttempt: Int = 0,
    val recoveryMaxAttempts: Int = 0,
    val tuning: TuningViewSnapshot? = null,
    val tunnelTest: TunnelTestSnapshot? = null,
    val meters: List<MeterEntrySnapshot> = emptyList(),
    val history: List<TelemetrySample> = emptyList(),
    val events: List<UiEventEntry> = emptyList(),
)

/**
 * Android `VpnService` owning the single tunnel lifecycle (CL-28, CL-29, CL-30, CL-31).
 *
 * - Runs as a foreground service (`specialUse`) with explicit `onRevoke()` cleanup and always
 *   calls `startForeground()` immediately on start to satisfy Android's FGS timing contract.
 * - Decrypts Keystore-sealed profile secrets into an ephemeral `0700`/`0600` runtime directory
 *   under `noBackupFilesDir/runtime/`, launches `libl2tunnel_android_service.so`, and immediately
 *   zeroes & deletes the ephemeral secret files once the Rust owner signals readiness (`R`) or stops.
 * - Brokers `VpnService.protect()` and `VpnService.Builder.establish()` (with per-app split
 *   tunneling and mandatory anti-loop self-exclusion) over `FdBrokerServer`.
 */
class L2TunnelVpnService : VpnService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycleLock = Any()
    private val active = AtomicBoolean(false)
    private val sessionToken = AtomicLong(0L)
    private val lastStartId = AtomicInteger(-1)
    private val lastRustOutput = AtomicReference<String?>(null)
    private val networkCoordinator = NetworkChangeCoordinator()
    private val secretStore = KeystoreSecretStore()

    private var broker: FdBrokerServer? = null
    private var childProcess: Process? = null
    private var apiClient: LocalApiV5Client? = null
    private var apiSocketFile: File? = null
    private var ephemeralRuntimeDir: File? = null
    private var pollJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var activeProfile: AndroidVpnProfile? = null
    private var lastEventCursor: Long = 0L

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        // Crash-recovery sweep: zero and delete any leftover ephemeral runtime secret dirs.
        val runtimeBase = File(noBackupFilesDir, "runtime")
        if (runtimeBase.exists()) {
            KeystoreSecretStore.scrubDirectory(runtimeBase)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        lastStartId.set(startId)
        when (intent?.action) {
            ACTION_STOP -> {
                requestStopTunnel("Disconnected", failed = false, detail = null)
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
            ACTION_TUNE_SWITCH -> {
                val repair = intent.getStringExtra(EXTRA_TUNE_REPAIR) ?: return START_STICKY
                val devMtu = intent.getIntExtra(EXTRA_TUNE_DEV_MTU, 1500)
                val pathMtu = intent.getIntExtra(EXTRA_TUNE_PATH_MTU, 1500)
                triggerTuningSwitch(TuningSettingSnapshot(repair, devMtu, pathMtu))
                return START_STICKY
            }
            ACTION_RATE_BUDGET -> {
                val sendBps = intent.getLongExtra(EXTRA_SEND_RATE_BPS, 0L)
                val recvBps = intent.getLongExtra(EXTRA_RECV_RATE_BPS, 0L)
                if (sendBps > 0L && recvBps > 0L) {
                    triggerRateBudget(sendBps, recvBps)
                }
                return START_STICKY
            }
            ACTION_TEST_PING -> {
                val count = intent.getIntExtra(EXTRA_TEST_COUNT, 5)
                triggerTestPing(count)
                return START_STICKY
            }
            ACTION_TEST_SPEED -> {
                val direction = intent.getStringExtra(EXTRA_TEST_DIRECTION) ?: "download"
                val streams = intent.getIntExtra(EXTRA_TEST_STREAMS, 4)
                val durationMs = intent.getIntExtra(EXTRA_TEST_DURATION_MS, 4000)
                triggerTestSpeed(direction, streams, durationMs)
                return START_STICKY
            }
            ACTION_TEST_CANCEL -> {
                val id = intent.getLongExtra(EXTRA_TEST_ID, 0L)
                if (id > 0L) triggerTestCancel(id)
                return START_STICKY
            }
            ACTION_START, null -> {
                val dirPath = intent?.getStringExtra(EXTRA_PROFILE_DIR)
                    ?: File(noBackupFilesDir, "profiles/default").absolutePath
                startTunnel(File(dirPath))
                return START_STICKY
            }
            else -> return START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by system; tearing down immediately")
        appendEvent("android", "VPN permission revoked by system")
        requestStopTunnel("VPN permission revoked", failed = false, detail = null)
        super.onRevoke()
    }

    override fun onDestroy() {
        teardownSessionSync(expectedToken = null, reason = "Stopped", failed = false, detail = null, stopService = false)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startTunnel(profileDir: File) {
        // Android requires startForeground() synchronously on every startForegroundService()
        // entry path (even if we abort immediately), otherwise API 26+ throws
        // ForegroundServiceDidNotStartInTimeException and kills the app process.
        startForegroundServiceNotification("Starting l2tunnel…")
        if (active.get()) {
            Log.i(TAG, "Ignoring duplicate start request while tunnel is active")
            return
        }
        val token = sessionToken.incrementAndGet()
        serviceScope.launch {
            startTunnelLocked(profileDir, token)
        }
    }

    private fun startTunnelLocked(profileDir: File, token: Long) {
        synchronized(lifecycleLock) {
            if (sessionToken.get() != token) return
            if (!active.compareAndSet(false, true)) {
                Log.i(TAG, "Ignoring duplicate start request while tunnel is active")
                return
            }
            // Always invoke VpnService.prepare() so ConnectivityService binds this package as the
            // active prepared VPN app before any VpnService.protect() or Builder.establish() call.
            if (VpnService.prepare(this) != null) {
                active.set(false)
                Log.w(TAG, "VPN permission not granted; user authorization via MainActivity required")
                publishState(
                    _uiState.value.copy(
                        running = false,
                        phase = "failed",
                        headline = "VPN permission required",
                        detail = "Grant VPN authorization in the app before connecting.",
                        profileName = profileDir.name,
                    ),
                )
                stopForegroundIfCurrent(token)
                return
            }
            val profile = try {
                AndroidVpnProfile.loadFromDirectory(profileDir)
            } catch (e: Exception) {
                active.set(false)
                publishState(
                    _uiState.value.copy(
                        running = false,
                        phase = "failed",
                        headline = "Invalid or missing profile",
                        detail = e.message,
                        profileName = profileDir.name,
                    ),
                )
                stopForegroundIfCurrent(token)
                return
            }
            activeProfile = profile
            lastEventCursor = 0L
            lastRustOutput.set(null)
            appendEvent("android", "Starting profile '${profileDir.name}' (${profile.cover})")
            updateNotification("Connecting to ${profile.udpPeer}…")
            publishState(
                VpnUiState(
                    running = true,
                    phase = "authenticating",
                    headline = "Connecting…",
                    peer = profile.udpPeer,
                    cover = profile.cover,
                    profileName = profileDir.name,
                    events = _uiState.value.events,
                ),
            )

            val runDir = File(filesDir, "run").apply {
                mkdirs()
                KeystoreSecretStore.setOwnerOnlyDir(this)
            }
            val sockFile = File(runDir, "service.sock")
            if (sockFile.exists()) {
                sockFile.delete()
            }
            apiSocketFile = sockFile
            apiClient = LocalApiV5Client(sockFile)

            // Materialize decrypted ephemeral secrets in `noBackupFilesDir/runtime/<run-id>/`
            // and scrub them immediately upon Rust readiness (`R`) or teardown.
            val runtimeStage = File(
                File(noBackupFilesDir, "runtime"),
                "run-${AndroidProcess.myPid()}-${BROKER_SEQ.incrementAndGet()}",
            )
            val materializedDir = try {
                secretStore.materializeRuntimeDirectory(profileDir, runtimeStage)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt Keystore profile secrets: ${e.message}")
                KeystoreSecretStore.scrubDirectory(runtimeStage)
                teardownLocked(
                    expectedToken = token,
                    reason = "Keystore decryption failed",
                    failed = true,
                    detail = e.message,
                    stopService = true,
                )
                return
            }
            ephemeralRuntimeDir = materializedDir

            val brokerName = "l2tunnel-vpn-${AndroidProcess.myPid()}-${BROKER_SEQ.incrementAndGet()}"
            val fdBroker = FdBrokerServer(
                abstractName = brokerName,
                protectFd = { rawFd -> protect(rawFd) },
                establishTun = { buildTunInterface(profile) },
                onReady = {
                    // Rust has already read all keys into memory; zero and delete plaintext copies now.
                    scrubEphemeralSecrets()
                    appendEvent("android", "Tunnel established; ephemeral secret staging wiped")
                    updateNotification("Connected · ${profile.udpPeer}")
                },
            )
            broker = fdBroker
            fdBroker.start()

            val binary = File(applicationInfo.nativeLibraryDir, NATIVE_BINARY_NAME)
            if (!binary.isFile || !binary.canExecute()) {
                teardownLocked(
                    expectedToken = token,
                    reason = "Missing native binary",
                    failed = true,
                    detail = "Missing executable ${binary.name}",
                    stopService = true,
                )
                return
            }

            try {
                val proc = ProcessBuilder(
                    binary.absolutePath,
                    materializedDir.absolutePath,
                    sockFile.absolutePath,
                    brokerName,
                )
                    .redirectErrorStream(true)
                    .start()
                childProcess = proc
                registerNetworkCallback()
                startSupervisionLoops(proc, profile, token)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start Rust Android service: ${e.message}")
                teardownLocked(
                    expectedToken = token,
                    reason = "Service launch failed",
                    failed = true,
                    detail = e.message,
                    stopService = true,
                )
            }
        }
    }

    private fun buildTunInterface(profile: AndroidVpnProfile): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("l2tunnel-${profile.profileDir.name}")
            .setMtu(profile.tunMtu)
            .addAddress(profile.tunAddress, profile.tunPrefixLength)
        for ((dest, prefix) in profile.resolveEffectiveRoutes()) {
            builder.addRoute(dest, prefix)
        }
        for (dns in profile.dnsServers) {
            builder.addDnsServer(dns)
        }
        val (allowed, disallowed) = profile.resolveSplitTunnelPackages(packageName)
        if (allowed.isNotEmpty()) {
            for (pkg in allowed) {
                try {
                    builder.addAllowedApplication(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "Skipping unknown allowed package $pkg: ${e.message}")
                }
            }
        } else {
            for (pkg in disallowed) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "Skipping unknown disallowed package $pkg: ${e.message}")
                }
            }
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
                    appendEvent("android", "Default network changed; triggering bounded reconnect")
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

    private fun startSupervisionLoops(proc: Process, profile: AndroidVpnProfile, token: Long) {
        pollJob?.cancel()
        pollJob = serviceScope.launch {
            val stderrJob = launch {
                try {
                    proc.inputStream.bufferedReader().forEachLine { line ->
                        val trimmed = line.trim()
                        if (trimmed.isNotEmpty()) {
                            lastRustOutput.set(trimmed)
                            appendEvent("rust", trimmed)
                        }
                        Log.i("L2TunnelRust", line)
                    }
                } catch (_: Exception) {
                }
            }
            launch {
                val exit = proc.waitFor()
                try {
                    // Let the stdout/stderr reader drain the final error line before publishing.
                    kotlinx.coroutines.withTimeoutOrNull(250L) { stderrJob.join() }
                } catch (_: Exception) {
                }
                if (sessionToken.get() == token && active.get()) {
                    val rustMsg = lastRustOutput.get()
                    Log.w(TAG, "Rust Android service exited unexpectedly (code=$exit): $rustMsg")
                    appendEvent("rust", "Service exited unexpectedly (code=$exit)")
                    teardownSessionSync(
                        expectedToken = token,
                        reason = if (exit == 0) "Disconnected" else "Tunnel service failed (exit $exit)",
                        failed = exit != 0,
                        detail = rustMsg,
                        stopService = true,
                    )
                }
            }
            var pollFailures = 0
            var pollTick = 0
            var prevSentBytes: Long? = null
            var prevRecvPkts: Long? = null
            var prevTimeMs: Long? = null
            while (isActive && active.get() && sessionToken.get() == token) {
                val client = apiClient
                if (client != null && apiSocketFile?.exists() == true) {
                    try {
                        val st = client.status()
                        val m = try { client.metrics() } catch (_: Exception) { null }
                        val c = try { client.carrierShow() } catch (_: Exception) { null }
                        val tuning = if (st.phase == "connected" && (pollTick % 3 == 0 || _uiState.value.tuning == null)) {
                            try { client.tuningGet() } catch (_: Exception) { _uiState.value.tuning }
                        } else {
                            _uiState.value.tuning
                        }
                        val testState = if (_uiState.value.tunnelTest?.state == "running" || pollTick % 4 == 0) {
                            try { client.testGet() } catch (_: Exception) { _uiState.value.tunnelTest }
                        } else {
                            _uiState.value.tunnelTest
                        }
                        val meters = if (st.phase == "connected" && pollTick % 3 == 0) {
                            try { client.metersRead(limit = 32) } catch (_: Exception) { _uiState.value.meters }
                        } else {
                            _uiState.value.meters
                        }
                        try {
                            val ev = client.events(lastEventCursor, limit = 24)
                            if (ev != null) {
                                lastEventCursor = ev.first
                                for (line in ev.second) {
                                    appendEvent("service", line)
                                }
                            }
                        } catch (_: Exception) {
                        }

                        pollFailures = 0
                        pollTick += 1

                        val nowMs = System.currentTimeMillis()
                        var txBps = 0f
                        var rxPps = 0f
                        if (m != null) {
                            val prevT = prevTimeMs
                            val prevTx = prevSentBytes
                            val prevRx = prevRecvPkts
                            if (prevT != null && prevTx != null && prevRx != null) {
                                val dtSec = ((nowMs - prevT).coerceAtLeast(100L)) / 1000f
                                if (m.wireSentBytes >= prevTx) {
                                    txBps = (m.wireSentBytes - prevTx) / dtSec
                                }
                                if (m.wireReceivedPackets >= prevRx) {
                                    rxPps = (m.wireReceivedPackets - prevRx) / dtSec
                                }
                            }
                            prevSentBytes = m.wireSentBytes
                            prevRecvPkts = m.wireReceivedPackets
                            prevTimeMs = nowMs
                        }

                        val sample = TelemetrySample(
                            timestampMs = nowMs,
                            txBytesPerSec = txBps,
                            rxPacketsPerSec = rxPps,
                            rttMs = m?.rttMicros?.let { it / 1000f },
                        )
                        val updatedHistory = (_uiState.value.history + sample).takeLast(MAX_HISTORY_SAMPLES)
                        val headline = formatHeadline(st)
                        val effectiveCover = c?.currentCover ?: st.cover ?: profile.cover
                        val currentState = _uiState.value
                        val effectiveDetail = st.terminalReason ?: if (st.phase == "failed") {
                            "Handshake/admission did not complete — check server address, UDP cover, and client/admission keys (see Stats & Logs)."
                        } else {
                            null
                        }
                        publishState(
                            currentState.copy(
                                running = true,
                                phase = st.phase,
                                headline = headline,
                                detail = effectiveDetail,
                                peer = st.peer ?: profile.udpPeer,
                                cover = effectiveCover,
                                carrierSwitches = c?.switches ?: currentState.carrierSwitches,
                                wireSentBytes = m?.wireSentBytes ?: currentState.wireSentBytes,
                                wireSentPackets = m?.wireSentPackets ?: currentState.wireSentPackets,
                                wireReceivedPackets = m?.wireReceivedPackets ?: currentState.wireReceivedPackets,
                                wireSendDrops = m?.wireSendDrops ?: currentState.wireSendDrops,
                                wireReceiveErrors = m?.wireReceiveErrors ?: currentState.wireReceiveErrors,
                                wireRejectedPackets = m?.wireRejectedPackets ?: currentState.wireRejectedPackets,
                                wireReplayRejections = m?.wireReplayRejections ?: currentState.wireReplayRejections,
                                nativeReadPackets = m?.nativeReadPackets ?: currentState.nativeReadPackets,
                                nativeWrittenPackets = m?.nativeWrittenPackets ?: currentState.nativeWrittenPackets,
                                nativeBackpressureDrops = m?.nativeBackpressureDrops ?: currentState.nativeBackpressureDrops,
                                txBytesPerSec = txBps,
                                rxPacketsPerSec = rxPps,
                                rttMicros = m?.rttMicros ?: currentState.rttMicros,
                                sendRateBytesPerSec = st.sendRateBytesPerSec ?: currentState.sendRateBytesPerSec,
                                receiveRateBytesPerSec = st.receiveRateBytesPerSec ?: currentState.receiveRateBytesPerSec,
                                profileName = profile.profileDir.name,
                                recoveryAttempt = st.recovery?.attempt ?: 0,
                                recoveryMaxAttempts = st.recovery?.maxAttempts ?: 0,
                                tuning = tuning,
                                tunnelTest = testState,
                                meters = meters,
                                history = updatedHistory,
                            ),
                        )
                        updateNotification("$headline · $effectiveCover")
                    } catch (e: Exception) {
                        pollFailures += 1
                        if (pollFailures <= 3 || pollFailures % 10 == 0) {
                            Log.w(TAG, "Local API v5 poll failed (#$pollFailures): ${e.javaClass.simpleName}: ${e.message}")
                        }
                    }
                }
                delay(1200L)
            }
        }
    }

    private fun triggerReconnect(reason: String) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                client.reconnect()
                appendEvent("android", "Submitted reconnect ($reason)")
                Log.i(TAG, "Submitted Local API v5 reconnect ($reason)")
            } catch (e: Exception) {
                appendEvent("android", "Reconnect failed: ${e.message}")
                Log.w(TAG, "Reconnect request failed ($reason): ${e.message}")
            }
        }
    }

    private fun triggerCarrierSwitch(target: String) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val res = client.carrierSwitch(target)
                appendEvent("android", "Live UDP cover switched -> ${res?.currentCover ?: target}")
                Log.i(TAG, "Carrier switch -> $target result=${res?.currentCover}")
            } catch (e: Exception) {
                appendEvent("android", "Cover switch to $target failed: ${e.message}")
                Log.w(TAG, "Carrier switch to $target failed: ${e.message}")
            }
        }
    }

    private fun triggerTuningSwitch(setting: TuningSettingSnapshot) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val reply = client.tuningSwitch(setting)
                val code = reply.optString("code", "ok")
                appendEvent("android", "Live tuning ${setting.repair} MTU=${setting.deviceMtu}: $code")
            } catch (e: Exception) {
                appendEvent("android", "Live tuning switch failed: ${e.message}")
            }
        }
    }

    private fun triggerRateBudget(sendBps: Long, recvBps: Long) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val reply = client.rateBudgetSet(sendBps, recvBps)
                val code = reply.optString("code", "ok")
                appendEvent(
                    "android",
                    "Speed budget ${sendBps * 8 / 1_000_000}/${recvBps * 8 / 1_000_000} Mbit/s: $code",
                )
            } catch (e: Exception) {
                appendEvent("android", "Speed budget update failed: ${e.message}")
            }
        }
    }

    private fun triggerTestPing(count: Int) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val snap = client.testStartPing(count = count)
                if (snap != null) {
                    publishState(_uiState.value.copy(tunnelTest = snap))
                }
                appendEvent("android", "Started in-process tunnel ping ($count probes)")
            } catch (e: Exception) {
                appendEvent("android", "Tunnel ping start failed: ${e.message}")
            }
        }
    }

    private fun triggerTestSpeed(direction: String, streams: Int, durationMs: Int) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val snap = client.testStartSpeed(direction, streams, durationMs)
                if (snap != null) {
                    publishState(_uiState.value.copy(tunnelTest = snap))
                }
                appendEvent("android", "Started in-process tunnel $direction test ($streams streams)")
            } catch (e: Exception) {
                appendEvent("android", "Tunnel speed start failed: ${e.message}")
            }
        }
    }

    private fun triggerTestCancel(id: Long) {
        val client = apiClient ?: return
        serviceScope.launch {
            try {
                val snap = client.testCancel(id)
                if (snap != null) {
                    publishState(_uiState.value.copy(tunnelTest = snap))
                }
                appendEvent("android", "Cancelled tunnel test #$id")
            } catch (e: Exception) {
                appendEvent("android", "Tunnel test cancel failed: ${e.message}")
            }
        }
    }

    private fun scrubEphemeralSecrets() {
        val dir = ephemeralRuntimeDir
        ephemeralRuntimeDir = null
        if (dir != null) {
            KeystoreSecretStore.scrubDirectory(dir)
        }
    }

    private fun requestStopTunnel(reason: String, failed: Boolean, detail: String?) {
        // Advance token immediately so any concurrent start or exit watcher yields,
        // and run process/broker teardown off the main thread to avoid UI stalls.
        val stopToken = sessionToken.incrementAndGet()
        serviceScope.launch {
            teardownSessionSync(
                expectedToken = stopToken,
                reason = reason,
                failed = failed,
                detail = detail,
                stopService = true,
            )
        }
    }

    private fun stopForegroundIfCurrent(token: Long) {
        if (sessionToken.get() == token) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            val id = lastStartId.get()
            if (id >= 0) {
                stopSelf(id)
            } else {
                stopSelf()
            }
        }
    }

    private fun teardownSessionSync(
        expectedToken: Long?,
        reason: String,
        failed: Boolean,
        detail: String?,
        stopService: Boolean,
    ) {
        synchronized(lifecycleLock) {
            teardownLocked(expectedToken, reason, failed, detail, stopService)
        }
    }

    private fun teardownLocked(
        expectedToken: Long?,
        reason: String,
        failed: Boolean,
        detail: String?,
        stopService: Boolean,
    ) {
        if (expectedToken != null && sessionToken.get() != expectedToken) {
            return
        }
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

        scrubEphemeralSecrets()

        apiSocketFile?.let { file ->
            if (file.exists()) file.delete()
        }
        apiSocketFile = null
        apiClient = null

        if (wasActive || _uiState.value.running) {
            appendEvent("android", "Tunnel stopped ($reason)")
            publishState(
                VpnUiState(
                    running = false,
                    phase = if (failed) "failed" else "disconnected",
                    headline = reason,
                    detail = detail,
                    profileName = activeProfile?.profileDir?.name,
                    events = _uiState.value.events,
                ),
            )
        }
        if (stopService && (expectedToken == null || sessionToken.get() == expectedToken)) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            val id = lastStartId.get()
            if (id >= 0) {
                stopSelf(id)
            } else {
                stopSelf()
            }
        }
    }

    private fun appendEvent(source: String, message: String) {
        val entry = UiEventEntry(System.currentTimeMillis(), source, message)
        val current = _uiState.value
        val next = (current.events + entry).takeLast(MAX_EVENT_ENTRIES)
        _uiState.value = current.copy(events = next)
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
        private const val MAX_HISTORY_SAMPLES = 60
        private const val MAX_EVENT_ENTRIES = 200
        private val BROKER_SEQ = AtomicLong(0L)

        const val ACTION_START = "dev.l2tunnel.android.action.START"
        const val ACTION_STOP = "dev.l2tunnel.android.action.STOP"
        const val ACTION_RECONNECT = "dev.l2tunnel.android.action.RECONNECT"
        const val ACTION_SWITCH_COVER = "dev.l2tunnel.android.action.SWITCH_COVER"
        const val ACTION_TUNE_SWITCH = "dev.l2tunnel.android.action.TUNE_SWITCH"
        const val ACTION_RATE_BUDGET = "dev.l2tunnel.android.action.RATE_BUDGET"
        const val ACTION_TEST_PING = "dev.l2tunnel.android.action.TEST_PING"
        const val ACTION_TEST_SPEED = "dev.l2tunnel.android.action.TEST_SPEED"
        const val ACTION_TEST_CANCEL = "dev.l2tunnel.android.action.TEST_CANCEL"

        const val EXTRA_PROFILE_DIR = "profile_dir"
        const val EXTRA_COVER = "cover"
        const val EXTRA_TUNE_REPAIR = "tune_repair"
        const val EXTRA_TUNE_DEV_MTU = "tune_dev_mtu"
        const val EXTRA_TUNE_PATH_MTU = "tune_path_mtu"
        const val EXTRA_SEND_RATE_BPS = "send_rate_bps"
        const val EXTRA_RECV_RATE_BPS = "recv_rate_bps"
        const val EXTRA_TEST_COUNT = "test_count"
        const val EXTRA_TEST_DIRECTION = "test_direction"
        const val EXTRA_TEST_STREAMS = "test_streams"
        const val EXTRA_TEST_DURATION_MS = "test_duration_ms"
        const val EXTRA_TEST_ID = "test_id"

        private val _uiState = MutableStateFlow(VpnUiState())
        val uiState: StateFlow<VpnUiState> = _uiState.asStateFlow()
    }
}

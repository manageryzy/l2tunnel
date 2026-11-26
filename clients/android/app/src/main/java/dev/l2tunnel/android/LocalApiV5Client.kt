package dev.l2tunnel.android

import android.net.LocalSocket
import android.net.LocalSocketAddress
import org.json.JSONObject
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/**
 * Pure length-delimited JSON framing matching `crates/l2tunnel-client-core/src/local/framing.rs`:
 * big-endian `u32` byte length followed by UTF-8 JSON (`version: 5`).
 */
object LocalApiV5Codec {
    const val VERSION: Int = 5
    const val REQUEST_LIMIT: Int = 4096
    const val RESPONSE_LIMIT: Int = 65536

    fun encodeRequest(action: JSONObject): ByteArray {
        val envelope = JSONObject()
            .put("version", VERSION)
            .put("action", action)
        val payload = envelope.toString().toByteArray(StandardCharsets.UTF_8)
        if (payload.isEmpty() || payload.size > REQUEST_LIMIT) {
            throw IOException("Local API v5 request exceeds bound (${payload.size} bytes)")
        }
        return payload
    }

    fun writeFrame(out: OutputStream, payload: ByteArray) {
        if (payload.isEmpty() || payload.size > REQUEST_LIMIT) {
            throw IOException("Local API v5 frame exceeds request bound")
        }
        val data = DataOutputStream(out)
        data.writeInt(payload.size)
        data.write(payload)
        data.flush()
    }

    fun readFrame(input: InputStream, maxBytes: Int = RESPONSE_LIMIT): JSONObject {
        val data = DataInputStream(input)
        val len = data.readInt()
        if (len <= 0 || len > maxBytes) {
            throw IOException("Local API v5 reply exceeds bound ($len bytes)")
        }
        val buf = ByteArray(len)
        data.readFully(buf)
        return JSONObject(String(buf, StandardCharsets.UTF_8))
    }

    fun parseStatus(reply: JSONObject): ServiceStatusSnapshot {
        val ok = reply.optBoolean("ok", false)
        val code = reply.optString("code", "").ifEmpty { null }
        val status = reply.optJSONObject("status")
        val observation = status?.optJSONObject("observation")
        val common = observation?.optJSONObject("common")
        val recoveryObj = status?.optJSONObject("recovery")
        val recovery = recoveryObj?.let {
            RecoverySnapshot(
                active = it.optBoolean("active", false),
                attempt = it.optInt("attempt", 0),
                maxAttempts = it.optInt("max_attempts", 0),
                reason = it.optString("reason", "").ifEmpty { null },
                nextRetryMs = optLongOrNull(it, "next_retry_ms"),
                totalRecoveries = it.optLong("total_recoveries", 0L),
            )
        }
        return ServiceStatusSnapshot(
            ok = ok,
            code = code,
            phase = status?.optString("phase", "unknown") ?: "unknown",
            nextRequestKey = status?.let { optLongOrNull(it, "next_request_key") },
            terminalReason = status?.optString("terminal_reason", "")?.ifEmpty { null },
            peer = common?.optString("peer", "")?.ifEmpty { null }
                ?: observation?.optString("peer", "")?.ifEmpty { null },
            carrier = common?.optString("carrier", "")?.ifEmpty { null }
                ?: observation?.optString("carrier", "")?.ifEmpty { null },
            cover = common?.optString("carrier", "")?.ifEmpty { null }
                ?: observation?.optString("udp_cover", "")?.ifEmpty { null },
            connectedMs = status?.let { optLongOrNull(it, "connected_ms") },
            sendRateBytesPerSec = common?.let { optLongOrNull(it, "send_rate") },
            receiveRateBytesPerSec = common?.let { optLongOrNull(it, "receive_rate") },
            eventCursor = status?.optLong("event_cursor", 0L) ?: 0L,
            recovery = recovery,
        )
    }

    fun parseMetrics(reply: JSONObject): MetricsSnapshot? {
        if (!reply.optBoolean("ok", false)) return null
        val m = reply.optJSONObject("metrics") ?: return null
        val wire = m.optJSONObject("wire")
        val dev = m.optJSONObject("device")
        return MetricsSnapshot(
            sampledMs = m.optLong("sampled_ms", 0L),
            wireSentBytes = wire?.optLong("sent_bytes", 0L) ?: 0L,
            wireSentPackets = wire?.optLong("sent_packets", 0L) ?: 0L,
            wireReceivedPackets = wire?.optLong("received_packets", 0L) ?: 0L,
            wireSendDrops = wire?.optLong("send_drops", 0L) ?: 0L,
            wireReceiveErrors = wire?.optLong("receive_errors", 0L) ?: 0L,
            wireRejectedPackets = wire?.optLong("rejected_packets", 0L) ?: 0L,
            wireReplayRejections = wire?.optLong("replay_rejections", 0L) ?: 0L,
            nativeReadPackets = dev?.optLong("read_packets", 0L) ?: 0L,
            nativeWrittenPackets = dev?.optLong("written_packets", 0L) ?: 0L,
            nativeBackpressureDrops = dev?.optLong("backpressure_drops", 0L) ?: 0L,
            rttMicros = optLongOrNull(m, "rtt_micros"),
        )
    }

    fun parseCarrier(reply: JSONObject): CarrierSnapshot? {
        if (!reply.optBoolean("ok", false)) return null
        val c = reply.optJSONObject("carrier_switch") ?: return null
        return CarrierSnapshot(
            supported = c.optBoolean("supported", true),
            currentCover = c.optString("current_cover", "").ifEmpty { null },
            local = c.optString("local", "").ifEmpty { null },
            peer = c.optString("peer", "").ifEmpty { null },
            switches = c.optLong("switches", 0L),
        )
    }

    fun parseTuning(reply: JSONObject): TuningViewSnapshot? {
        if (!reply.optBoolean("ok", false)) return null
        val t = reply.optJSONObject("tuning") ?: return null
        val current = t.optJSONObject("current")?.let { parseTuningSetting(it) }
        val repairs = mutableListOf<String>()
        t.optJSONArray("repair")?.let { arr ->
            for (i in 0 until arr.length()) repairs.add(arr.getString(i))
        }
        val devMtus = mutableListOf<Int>()
        t.optJSONArray("device_mtu")?.let { arr ->
            for (i in 0 until arr.length()) devMtus.add(arr.getInt(i))
        }
        val pathMtus = mutableListOf<Int>()
        t.optJSONArray("path_mtu")?.let { arr ->
            for (i in 0 until arr.length()) pathMtus.add(arr.getInt(i))
        }
        val entries = mutableListOf<TuningSettingSnapshot>()
        t.optJSONArray("entries")?.let { arr ->
            for (i in 0 until arr.length()) {
                entries.add(parseTuningSetting(arr.getJSONObject(i)))
            }
        }
        return TuningViewSnapshot(
            live = t.optBoolean("live", false),
            current = current,
            repairChoices = repairs,
            deviceMtuChoices = devMtus,
            pathMtuChoices = pathMtus,
            entries = entries,
        )
    }

    private fun parseTuningSetting(obj: JSONObject): TuningSettingSnapshot =
        TuningSettingSnapshot(
            repair = obj.optString("repair", "off"),
            deviceMtu = obj.optInt("device_mtu", 1500),
            pathMtu = obj.optInt("path_mtu", 1500),
        )

    fun parseTunnelTest(reply: JSONObject): TunnelTestSnapshot? {
        if (!reply.optBoolean("ok", false)) return null
        val outer = reply.optJSONObject("test") ?: return null
        val t = outer.optJSONObject("test") ?: return null
        val pingObj = t.optJSONObject("ping")
        val ping = pingObj?.let {
            PingTestResult(
                sent = it.optInt("sent", 0),
                received = it.optInt("received", 0),
                minUs = optLongOrNull(it, "min_us"),
                avgUs = optLongOrNull(it, "avg_us"),
                maxUs = optLongOrNull(it, "max_us"),
            )
        }
        return TunnelTestSnapshot(
            id = t.optLong("id", 0L),
            kind = t.optString("kind", ""),
            state = t.optString("state", "unknown"),
            direction = t.optString("direction", "").ifEmpty { null },
            streams = if (t.has("streams") && !t.isNull("streams")) t.optInt("streams") else null,
            elapsedMs = t.optLong("elapsed_ms", 0L),
            bytes = t.optLong("bytes", 0L),
            bitsPerSecond = t.optLong("bits_per_second", 0L),
            ping = ping,
            error = t.optString("error", "").ifEmpty { null },
        )
    }

    fun parseMeters(reply: JSONObject): List<MeterEntrySnapshot> {
        if (!reply.optBoolean("ok", false)) return emptyList()
        val page = reply.optJSONObject("meters") ?: return emptyList()
        val arr = page.optJSONArray("entries") ?: return emptyList()
        val out = ArrayList<MeterEntrySnapshot>(arr.length())
        for (i in 0 until arr.length()) {
            val e = arr.getJSONObject(i)
            out.add(MeterEntrySnapshot(e.optString("path", ""), e.optLong("value", 0L)))
        }
        return out
    }

    fun parseEvents(reply: JSONObject): Pair<Long, List<String>>? {
        if (!reply.optBoolean("ok", false)) return null
        val batch = reply.optJSONObject("events") ?: return null
        val next = batch.optLong("next", 0L)
        val arr = batch.optJSONArray("events")
        val out = mutableListOf<String>()
        if (arr != null) {
            for (i in 0 until arr.length()) {
                val item = arr.getJSONObject(i)
                val seq = item.optLong("sequence", 0L)
                val body = item.optJSONObject("event")
                val type = body?.optString("type", "event") ?: "event"
                val detail = when (type) {
                    "lifecycle" -> "phase=${body?.optString("phase", "?")}"
                    "operation_accepted" -> "op#${body?.optLong("operation")} ${body?.optString("kind")} accepted"
                    "operation_progress" -> "op#${body?.optLong("operation")} stage=${body?.optString("stage")}"
                    "operation_completed" -> "op#${body?.optLong("operation")} outcome=${body?.optString("outcome")}"
                    else -> type
                }
                out.add("#$seq $detail")
            }
        }
        return next to out
    }

    private fun optLongOrNull(obj: JSONObject, key: String): Long? =
        if (obj.has(key) && !obj.isNull(key)) obj.optLong(key) else null
}

data class RecoverySnapshot(
    val active: Boolean,
    val attempt: Int,
    val maxAttempts: Int,
    val reason: String?,
    val nextRetryMs: Long?,
    val totalRecoveries: Long,
)

data class ServiceStatusSnapshot(
    val ok: Boolean,
    val code: String?,
    val phase: String,
    val nextRequestKey: Long?,
    val terminalReason: String?,
    val peer: String?,
    val carrier: String?,
    val cover: String?,
    val connectedMs: Long?,
    val sendRateBytesPerSec: Long? = null,
    val receiveRateBytesPerSec: Long? = null,
    val eventCursor: Long = 0L,
    val recovery: RecoverySnapshot?,
)

data class MetricsSnapshot(
    val sampledMs: Long = 0L,
    val wireSentBytes: Long,
    val wireSentPackets: Long = 0L,
    val wireReceivedPackets: Long,
    val wireSendDrops: Long = 0L,
    val wireReceiveErrors: Long = 0L,
    val wireRejectedPackets: Long = 0L,
    val wireReplayRejections: Long = 0L,
    val nativeReadPackets: Long,
    val nativeWrittenPackets: Long,
    val nativeBackpressureDrops: Long = 0L,
    val rttMicros: Long?,
)

data class CarrierSnapshot(
    val supported: Boolean,
    val currentCover: String?,
    val local: String?,
    val peer: String?,
    val switches: Long,
)

data class TuningSettingSnapshot(
    val repair: String,
    val deviceMtu: Int,
    val pathMtu: Int,
)

data class TuningViewSnapshot(
    val live: Boolean,
    val current: TuningSettingSnapshot?,
    val repairChoices: List<String>,
    val deviceMtuChoices: List<Int>,
    val pathMtuChoices: List<Int>,
    val entries: List<TuningSettingSnapshot>,
)

data class PingTestResult(
    val sent: Int,
    val received: Int,
    val minUs: Long?,
    val avgUs: Long?,
    val maxUs: Long?,
)

data class TunnelTestSnapshot(
    val id: Long,
    val kind: String,
    val state: String,
    val direction: String?,
    val streams: Int?,
    val elapsedMs: Long,
    val bytes: Long,
    val bitsPerSecond: Long,
    val ping: PingTestResult?,
    val error: String?,
)

data class MeterEntrySnapshot(
    val path: String,
    val value: Long,
)

/**
 * Blocking Local API v5 client over the app-private Unix domain socket (`filesDir/run/service.sock`).
 * Callers run methods on `Dispatchers.IO`.
 */
class LocalApiV5Client(
    private val socketPath: File,
    private val timeoutMs: Int = 4000,
) {
    fun request(action: JSONObject): JSONObject {
        val socket = LocalSocket(LocalSocket.SOCKET_STREAM)
        return socket.use { s ->
            s.connect(
                LocalSocketAddress(
                    socketPath.absolutePath,
                    LocalSocketAddress.Namespace.FILESYSTEM,
                ),
            )
            // Android's LocalSocket only allocates the native FD inside connect().
            s.soTimeout = timeoutMs
            val encoded = LocalApiV5Codec.encodeRequest(action)
            LocalApiV5Codec.writeFrame(s.outputStream, encoded)
            LocalApiV5Codec.readFrame(s.inputStream)
        }
    }

    fun status(): ServiceStatusSnapshot =
        LocalApiV5Codec.parseStatus(request(JSONObject().put("command", "status")))

    fun metrics(): MetricsSnapshot? =
        LocalApiV5Codec.parseMetrics(request(JSONObject().put("command", "metrics")))

    fun carrierShow(): CarrierSnapshot? =
        LocalApiV5Codec.parseCarrier(request(JSONObject().put("command", "carrier_switch_get")))

    fun carrierSwitch(target: String): CarrierSnapshot? =
        LocalApiV5Codec.parseCarrier(
            request(JSONObject().put("command", "carrier_switch").put("target", target)),
        )

    fun tuningGet(): TuningViewSnapshot? =
        LocalApiV5Codec.parseTuning(request(JSONObject().put("command", "tuning_get")))

    fun tuningSwitch(setting: TuningSettingSnapshot): JSONObject {
        val key = status().nextRequestKey
            ?: throw IOException("Local API v5 status did not supply next_request_key")
        return request(
            JSONObject()
                .put("command", "tuning_switch")
                .put("request_key", key)
                .put(
                    "setting",
                    JSONObject()
                        .put("repair", setting.repair)
                        .put("device_mtu", setting.deviceMtu)
                        .put("path_mtu", setting.pathMtu),
                ),
        )
    }

    fun rateBudgetSet(sendBytesPerSec: Long, receiveBytesPerSec: Long): JSONObject =
        request(
            JSONObject()
                .put("command", "rate_budget_set")
                .put("send_rate", sendBytesPerSec)
                .put("receive_rate", receiveBytesPerSec),
        )

    fun testStartPing(count: Int = 5, intervalMs: Int = 150): TunnelTestSnapshot? =
        LocalApiV5Codec.parseTunnelTest(
            request(
                JSONObject()
                    .put("command", "test_start")
                    .put(
                        "test",
                        JSONObject()
                            .put("kind", "ping")
                            .put("count", count)
                            .put("interval_ms", intervalMs),
                    ),
            ),
        )

    fun testStartSpeed(
        direction: String = "download",
        streams: Int = 4,
        durationMs: Int = 4000,
    ): TunnelTestSnapshot? =
        LocalApiV5Codec.parseTunnelTest(
            request(
                JSONObject()
                    .put("command", "test_start")
                    .put(
                        "test",
                        JSONObject()
                            .put("kind", "speed")
                            .put("direction", direction)
                            .put("streams", streams)
                            .put("duration_ms", durationMs),
                    ),
            ),
        )

    fun testGet(id: Long? = null, timeoutMs: Int = 0): TunnelTestSnapshot? {
        val req = JSONObject()
            .put("command", "test_get")
            .put("timeout_ms", timeoutMs)
        if (id != null) req.put("id", id)
        return LocalApiV5Codec.parseTunnelTest(request(req))
    }

    fun testCancel(id: Long): TunnelTestSnapshot? =
        LocalApiV5Codec.parseTunnelTest(
            request(JSONObject().put("command", "test_cancel").put("id", id)),
        )

    fun metersRead(prefix: String = "", limit: Int = 32): List<MeterEntrySnapshot> =
        LocalApiV5Codec.parseMeters(
            request(
                JSONObject()
                    .put("command", "meters_read")
                    .put("side", "local")
                    .put("prefix", prefix)
                    .put("limit", limit),
            ),
        )

    fun events(after: Long, limit: Int = 32): Pair<Long, List<String>>? =
        LocalApiV5Codec.parseEvents(
            request(
                JSONObject()
                    .put("command", "events")
                    .put("after", after)
                    .put("limit", limit)
                    .put("timeout_ms", 0),
            ),
        )

    fun reconnect(): JSONObject {
        val key = status().nextRequestKey
            ?: throw IOException("Local API v5 status did not supply next_request_key")
        return request(JSONObject().put("command", "reconnect").put("request_key", key))
    }

    fun disconnect(): JSONObject {
        val key = status().nextRequestKey
            ?: throw IOException("Local API v5 status did not supply next_request_key")
        return request(JSONObject().put("command", "disconnect").put("request_key", key))
    }
}

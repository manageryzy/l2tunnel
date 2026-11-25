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
        envelope.put("version", VERSION)
        val keys = action.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            envelope.put(k, action.get(k))
        }
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
        val recoveryObj = status?.optJSONObject("recovery")
        val recovery = recoveryObj?.let {
            RecoverySnapshot(
                active = it.optBoolean("active", false),
                attempt = it.optInt("attempt", 0),
                maxAttempts = it.optInt("max_attempts", 0),
                reason = it.optString("reason", "").ifEmpty { null },
                nextRetryMs = if (it.has("next_retry_ms") && !it.isNull("next_retry_ms")) {
                    it.optLong("next_retry_ms")
                } else {
                    null
                },
                totalRecoveries = it.optLong("total_recoveries", 0L),
            )
        }
        return ServiceStatusSnapshot(
            ok = ok,
            code = code,
            phase = status?.optString("phase", "unknown") ?: "unknown",
            nextRequestKey = if (status != null && status.has("next_request_key") && !status.isNull("next_request_key")) {
                status.optLong("next_request_key")
            } else {
                null
            },
            terminalReason = status?.optString("terminal_reason", "")?.ifEmpty { null },
            peer = observation?.optString("peer", "")?.ifEmpty { null },
            carrier = observation?.optString("carrier", "")?.ifEmpty { null },
            cover = observation?.optString("udp_cover", "")?.ifEmpty { null },
            connectedMs = if (status != null && status.has("connected_ms") && !status.isNull("connected_ms")) {
                status.optLong("connected_ms")
            } else {
                null
            },
            recovery = recovery,
        )
    }

    fun parseMetrics(reply: JSONObject): MetricsSnapshot? {
        if (!reply.optBoolean("ok", false)) return null
        val m = reply.optJSONObject("metrics") ?: return null
        val wire = m.optJSONObject("wire")
        val dev = m.optJSONObject("device")
        return MetricsSnapshot(
            wireSentBytes = wire?.optLong("sent_bytes", 0L) ?: 0L,
            wireReceivedPackets = wire?.optLong("received_packets", 0L) ?: 0L,
            nativeReadPackets = dev?.optLong("read_packets", 0L) ?: 0L,
            nativeWrittenPackets = dev?.optLong("written_packets", 0L) ?: 0L,
            rttMicros = if (m.has("rtt_micros") && !m.isNull("rtt_micros")) m.optLong("rtt_micros") else null,
        )
    }

    fun parseCarrier(reply: JSONObject): CarrierSnapshot? {
        if (!reply.optBoolean("ok", false)) return null
        val c = reply.optJSONObject("carrier_switch") ?: return null
        return CarrierSnapshot(
            supported = c.optBoolean("supported", false),
            currentCover = c.optString("current_cover", "").ifEmpty { null },
            local = c.optString("local", "").ifEmpty { null },
            peer = c.optString("peer", "").ifEmpty { null },
            switches = c.optLong("switches", 0L),
        )
    }
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
    val recovery: RecoverySnapshot?,
)

data class MetricsSnapshot(
    val wireSentBytes: Long,
    val wireReceivedPackets: Long,
    val nativeReadPackets: Long,
    val nativeWrittenPackets: Long,
    val rttMicros: Long?,
)

data class CarrierSnapshot(
    val supported: Boolean,
    val currentCover: String?,
    val local: String?,
    val peer: String?,
    val switches: Long,
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
        val socket = LocalSocket()
        return socket.use { s ->
            s.soTimeout = timeoutMs
            s.connect(
                LocalSocketAddress(
                    socketPath.absolutePath,
                    LocalSocketAddress.Namespace.FILESYSTEM,
                ),
            )
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

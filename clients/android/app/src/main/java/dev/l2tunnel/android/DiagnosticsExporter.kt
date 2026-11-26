package dev.l2tunnel.android

import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

/**
 * Redacted diagnostic report exporter matching desktop `CL-16`:
 * excludes all private keys, tokens, and user payload, and redacts IP endpoints by default.
 */
object DiagnosticsExporter {
    private val IPV4_REGEX = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b""")

    fun redactAddresses(text: String): String =
        IPV4_REGEX.replace(text, "<redacted-ip>")

    fun buildReportJson(
        appVersion: String,
        state: VpnUiState,
        activeProfile: StoredProfileSummary?,
        redactEndpoints: Boolean = true,
    ): String {
        fun clean(value: String?): String? =
            if (value == null) null else if (redactEndpoints) redactAddresses(value) else value

        val root = JSONObject()
            .put("schema", "l2tunnel-android-diagnostics-v1")
            .put("redacted", redactEndpoints)
            .put(
                "environment",
                JSONObject()
                    .put("app_version", appVersion)
                    .put("android_release", Build.VERSION.RELEASE ?: "unknown")
                    .put("api_level", Build.VERSION.SDK_INT)
                    .put("supported_abis", JSONArray(Build.SUPPORTED_ABIS?.toList() ?: emptyList<String>())),
            )
            .put(
                "capabilities",
                JSONObject()
                    .put("layer", "tun_l3_only")
                    .put("tap_supported", false)
                    .put("vxlan_supported", false)
                    .put("vpn_service_protect", true)
                    .put("keystore_envelope_encryption", true),
            )
            .put(
                "session",
                JSONObject()
                    .put("running", state.running)
                    .put("phase", state.phase)
                    .put("headline", clean(state.headline))
                    .put("detail", clean(state.detail))
                    .put("peer", clean(state.peer))
                    .put("cover", state.cover)
                    .put("rtt_micros", state.rttMicros)
                    .put("wire_sent_bytes", state.wireSentBytes)
                    .put("wire_sent_packets", state.wireSentPackets)
                    .put("wire_received_packets", state.wireReceivedPackets)
                    .put("wire_send_drops", state.wireSendDrops)
                    .put("wire_receive_errors", state.wireReceiveErrors)
                    .put("wire_rejected_packets", state.wireRejectedPackets)
                    .put("wire_replay_rejections", state.wireReplayRejections)
                    .put("native_read_packets", state.nativeReadPackets)
                    .put("native_written_packets", state.nativeWrittenPackets)
                    .put("carrier_switches", state.carrierSwitches),
            )

        if (activeProfile != null) {
            val prof = activeProfile.profile
            root.put(
                "active_profile",
                JSONObject()
                    .put("id", activeProfile.id)
                    .put("valid", activeProfile.isValid)
                    .put("keystore_sealed", activeProfile.keystoreSealed)
                    .put("peer_key_sha256_prefix", activeProfile.peerKeyFingerprint)
                    .put("secret_files_present", JSONArray(activeProfile.presentSecrets))
                    .put("cover", prof?.cover)
                    .put("noise_profile", prof?.noiseProfile)
                    .put("path_mtu", prof?.pathMtu)
                    .put("tun_mtu", prof?.tunMtu)
                    .put("split_tunnel_mode", prof?.splitTunnelMode?.wire)
                    .put("split_tunnel_app_count", prof?.splitTunnelApps?.size ?: 0)
                    .put("udp_peer", clean(prof?.udpPeer)),
            )
        }

        val metersArr = JSONArray()
        for (m in state.meters.take(64)) {
            metersArr.put(JSONObject().put("path", m.path).put("value", m.value))
        }
        root.put("meters", metersArr)

        val eventsArr = JSONArray()
        for (e in state.events.takeLast(100)) {
            eventsArr.put(
                JSONObject()
                    .put("timestamp_ms", e.timestampMs)
                    .put("source", e.source)
                    .put("message", clean(e.message)),
            )
        }
        root.put("events", eventsArr)
        return root.toString(2) + "\n"
    }
}

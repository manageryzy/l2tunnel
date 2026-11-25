package dev.l2tunnel.android

import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** Explicit refusal for unsupported L2/VXLAN attachments on standard Android VpnService (CL-28). */
class UnsupportedLayerException(message: String) : IllegalArgumentException(message)

/**
 * Validated Android L3 VPN profile combining the Rust native client manifest (`client.json`)
 * and optional Android `VpnService.Builder` interface parameters (`android_vpn.json`).
 *
 * Standard Android `VpnService` is strictly TUN (L3). TAP and VXLAN L2 attachments are
 * refused explicitly and never silently fabricated.
 */
data class AndroidVpnProfile(
    val profileDir: File,
    val cover: String,
    val udpBind: String,
    val udpPeer: String,
    val pathMtu: Int,
    val tunMtu: Int,
    val noiseProfile: String,
    val handshakeSeconds: Int,
    val tunAddress: String,
    val tunPrefixLength: Int,
    val routes: List<Pair<String, Int>>,
    val dnsServers: List<String>,
) {
    companion object {
        const val DEFAULT_TUN_ADDRESS = "10.231.0.2"
        const val DEFAULT_TUN_PREFIX = 30
        val DEFAULT_ROUTES: List<Pair<String, Int>> = listOf("0.0.0.0" to 0)
        val DEFAULT_DNS: List<String> = listOf("1.1.1.1")

        private val SUPPORTED_COVERS = setOf("quic-like", "media-like", "tls-like")
        private val SUPPORTED_NOISE = setOf("ik", "ikpsk2")

        /**
         * Parse and validate `client.json` (plus optional `android_vpn.json`) from JSON text.
         * Never logs or exposes private key material.
         */
        fun parse(
            profileDir: File,
            clientJsonText: String,
            androidVpnJsonText: String? = null,
        ): AndroidVpnProfile {
            val client = JSONObject(clientJsonText)
            val version = client.optInt("version", -1)
            require(version == 1) { "client.json version must be 1" }

            val carrier = client.optString("carrier", "")
            require(carrier == "udp") { "Android VpnService profile requires carrier=\"udp\"" }

            if (client.has("layer") && !client.isNull("layer")) {
                val layer = client.getString("layer").trim().lowercase()
                if (layer != "tun") {
                    throw UnsupportedLayerException(
                        "Android VpnService only supports TUN (L3); layer=\"$layer\" (TAP/VXLAN L2) is unsupported",
                    )
                }
            }
            if (client.has("vxlan_vni") || client.has("vxlan_bind") || client.has("vxlan_peer")) {
                throw UnsupportedLayerException(
                    "VXLAN L2 overlay attachment is unsupported on standard Android VpnService",
                )
            }

            val cover = client.optString("cover", "")
            require(cover in SUPPORTED_COVERS) { "Unsupported UDP cover: $cover" }

            val noiseProfile = client.optString("noise_profile", "")
            require(noiseProfile in SUPPORTED_NOISE) { "Unsupported Noise profile: $noiseProfile" }

            val udpBind = client.optString("udp_bind", "").trim()
            val udpPeer = client.optString("udp_peer", "").trim()
            require(udpBind.isNotEmpty() && udpPeer.isNotEmpty()) {
                "udp_bind and udp_peer are required"
            }
            require(udpBind != udpPeer) { "udp_bind must differ from udp_peer" }

            val pathMtu = client.optInt("path_mtu", 0)
            val tunMtu = client.optInt("tun_mtu", 0)
            val handshakeSeconds = client.optInt("handshake_seconds", 0)
            require(pathMtu in 1280..65535) { "path_mtu must be in 1280..65535" }
            require(tunMtu in 1280..65519) { "tun_mtu must be in 1280..65519" }
            require(handshakeSeconds in 1..120) { "handshake_seconds must be in 1..120" }

            var tunAddress = DEFAULT_TUN_ADDRESS
            var tunPrefix = DEFAULT_TUN_PREFIX
            var routes = DEFAULT_ROUTES
            var dns = DEFAULT_DNS

            if (!androidVpnJsonText.isNullOrBlank()) {
                val vpn = JSONObject(androidVpnJsonText)
                if (vpn.has("tun_address")) {
                    tunAddress = vpn.getString("tun_address").trim()
                    require(tunAddress.isNotEmpty()) { "tun_address must not be empty" }
                }
                if (vpn.has("tun_prefix")) {
                    tunPrefix = vpn.getInt("tun_prefix")
                    require(tunPrefix in 1..128) { "tun_prefix must be in 1..128" }
                }
                if (vpn.has("routes")) {
                    routes = parseCidrs(vpn.getJSONArray("routes"))
                    require(routes.isNotEmpty()) { "routes must not be empty" }
                }
                if (vpn.has("dns")) {
                    val arr = vpn.getJSONArray("dns")
                    val list = mutableListOf<String>()
                    for (i in 0 until arr.length()) {
                        val entry = arr.getString(i).trim()
                        require(entry.isNotEmpty()) { "DNS server entry must not be empty" }
                        list.add(entry)
                    }
                    dns = list
                }
            }

            return AndroidVpnProfile(
                profileDir = profileDir,
                cover = cover,
                udpBind = udpBind,
                udpPeer = udpPeer,
                pathMtu = pathMtu,
                tunMtu = tunMtu,
                noiseProfile = noiseProfile,
                handshakeSeconds = handshakeSeconds,
                tunAddress = tunAddress,
                tunPrefixLength = tunPrefix,
                routes = routes,
                dnsServers = dns,
            )
        }

        fun loadFromDirectory(profileDir: File): AndroidVpnProfile {
            val clientFile = File(profileDir, "client.json")
            require(clientFile.isFile) { "Missing ${clientFile.name} in ${profileDir.name}" }
            val requiredFiles = listOf("common.json", "noise-private.key", "noise-peer.pub", "member.pk8", "admission.key")
            for (name in requiredFiles) {
                require(File(profileDir, name).isFile) { "Missing required profile file: $name" }
            }
            val vpnFile = File(profileDir, "android_vpn.json")
            val vpnText = if (vpnFile.isFile) vpnFile.readText() else null
            return parse(profileDir, clientFile.readText(), vpnText)
        }

        private fun parseCidrs(array: JSONArray): List<Pair<String, Int>> {
            val out = mutableListOf<Pair<String, Int>>()
            for (i in 0 until array.length()) {
                val raw = array.getString(i).trim()
                val parts = raw.split("/")
                require(parts.size == 2) { "Invalid CIDR route: $raw" }
                val prefix = parts[1].toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid CIDR prefix in route: $raw")
                require(prefix in 0..128) { "CIDR prefix out of range: $raw" }
                out.add(parts[0] to prefix)
            }
            return out
        }
    }
}

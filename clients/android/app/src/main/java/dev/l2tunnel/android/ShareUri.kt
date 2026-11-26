package dev.l2tunnel.android

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Byte-exact Kotlin codec for the shared `l2tunnel://v1/connect?...` URI format
 * (`crates/l2tunnel-client-core/src/local/share_uri.rs`).
 *
 * Public URIs contain ONLY non-secret connection & server trust parameters (`peer`, `cover`,
 * `noise`, `peer_pub`, MTUs, `tun`, `routes`, `dns`, `tune_repair`). Private secrets
 * (`adm`, `key`, `member`, `psk`) are included ONLY on explicit opt-in and never logged.
 */
data class ShareSecrets(
    val admission: ByteArray? = null,
    val noisePrivate: ByteArray? = null,
    val memberPk8: ByteArray? = null,
    val noisePsk: ByteArray? = null,
) {
    val isEmpty: Boolean
        get() = admission == null && noisePrivate == null && memberPk8 == null && noisePsk == null

    fun zeroize() {
        admission?.fill(0)
        noisePrivate?.fill(0)
        memberPk8?.fill(0)
        noisePsk?.fill(0)
    }

    override fun toString(): String =
        "ShareSecrets(adm=${admission != null}, key=${noisePrivate != null}, member=${memberPk8 != null}, psk=${noisePsk != null})"
}

data class ShareProfileUri(
    val name: String? = null,
    val peer: String,
    val cover: String = "quic-like",
    val noise: String = "ik",
    val peerPub: ByteArray? = null,
    val tunMtu: Int = 1500,
    val pathMtu: Int = 1500,
    val handshakeSeconds: Int = 30,
    val tun: String? = null,
    val routes: List<String> = emptyList(),
    val dns: List<String> = emptyList(),
    val tuneRepair: String? = null,
    val tuneDeviceMtu: String? = null,
    val tunePathMtu: String? = null,
    val secrets: ShareSecrets = ShareSecrets(),
) {
    fun encode(): String {
        validate()
        val pairs = ArrayList<Pair<String, String>>()
        if (!name.isNullOrBlank()) pairs.add("name" to percentEncode(name))
        pairs.add("peer" to percentEncode(peer))
        pairs.add("cover" to cover)
        pairs.add("noise" to noise)
        peerPub?.let { pairs.add("peer_pub" to hexEncode(it)) }
        if (tunMtu != 1500) pairs.add("mtu" to tunMtu.toString())
        if (pathMtu != 1500) pairs.add("path_mtu" to pathMtu.toString())
        if (handshakeSeconds != 30) pairs.add("hs" to handshakeSeconds.toString())
        if (!tun.isNullOrBlank()) pairs.add("tun" to percentEncode(tun))
        if (routes.isNotEmpty()) pairs.add("routes" to percentEncode(routes.joinToString(",")))
        if (dns.isNotEmpty()) pairs.add("dns" to percentEncode(dns.joinToString(",")))
        if (!tuneRepair.isNullOrBlank()) pairs.add("tune_repair" to percentEncode(tuneRepair.trim()))
        if (!tuneDeviceMtu.isNullOrBlank()) pairs.add("tune_device_mtu" to percentEncode(tuneDeviceMtu.trim()))
        if (!tunePathMtu.isNullOrBlank()) pairs.add("tune_path_mtu" to percentEncode(tunePathMtu.trim()))
        secrets.admission?.let { pairs.add("adm" to hexEncode(it)) }
        secrets.noisePrivate?.let { pairs.add("key" to hexEncode(it)) }
        secrets.memberPk8?.let { pairs.add("member" to base64UrlEncode(it)) }
        secrets.noisePsk?.let { pairs.add("psk" to hexEncode(it)) }
        val encoded = PREFIX + "?" + pairs.joinToString("&") { "${it.first}=${it.second}" }
        require(encoded.length <= MAX_URI_BYTES) { "Encoded share URI exceeds $MAX_URI_BYTES bytes" }
        return encoded
    }

    fun validate() {
        require(peer.isNotBlank() && peer.contains(':') && !peer.any { it.isWhitespace() }) {
            "peer must be a valid host:port"
        }
        require(cover in AndroidVpnProfile.SUPPORTED_COVERS) { "Unsupported UDP cover: $cover" }
        require(noise in AndroidVpnProfile.SUPPORTED_NOISE) { "Unsupported Noise profile: $noise" }
        require(tunMtu in 1280..65519) { "mtu must be in 1280..65519" }
        require(pathMtu in 1280..65535) { "path_mtu must be in 1280..65535" }
        require(handshakeSeconds in 1..120) { "hs must be in 1..120" }
        if (peerPub != null) require(peerPub.size == 32) { "peer_pub must be 32 bytes" }
        if (secrets.admission != null) require(secrets.admission.size == 32) { "adm must be 32 bytes" }
        if (secrets.noisePrivate != null) require(secrets.noisePrivate.size == 32) { "key must be 32 bytes" }
        if (secrets.noisePsk != null) {
            require(secrets.noisePsk.size == 32) { "psk must be 32 bytes" }
            require(noise == "ikpsk2") { "psk requires noise=ikpsk2" }
        }
        if (secrets.memberPk8 != null) {
            require(secrets.memberPk8.size in 32..MAX_MEMBER_DER_BYTES) {
                "member PKCS#8 length out of bounds"
            }
        }
        if (!tun.isNullOrBlank()) validateCidr(tun)
        routes.forEach { validateCidr(it) }
    }

    fun toAndroidVpnProfile(profileDir: File): AndroidVpnProfile {
        val (tunAddr, tunPrefix) = if (!tun.isNullOrBlank()) {
            val parts = tun.split('/')
            parts[0] to parts[1].toInt()
        } else {
            AndroidVpnProfile.DEFAULT_TUN_ADDRESS to AndroidVpnProfile.DEFAULT_TUN_PREFIX
        }
        val parsedRoutes = if (routes.isNotEmpty()) {
            AndroidVpnProfile.parseCidrsText(routes.joinToString(","))
        } else {
            AndroidVpnProfile.DEFAULT_ROUTES
        }
        return AndroidVpnProfile(
            profileDir = profileDir,
            cover = cover,
            udpBind = "0.0.0.0:0",
            udpPeer = peer,
            pathMtu = pathMtu,
            tunMtu = tunMtu,
            noiseProfile = noise,
            handshakeSeconds = handshakeSeconds,
            tuneRepair = tuneRepair,
            tuneDeviceMtu = tuneDeviceMtu,
            tunePathMtu = tunePathMtu,
            tunAddress = tunAddr,
            tunPrefixLength = tunPrefix,
            routes = parsedRoutes,
            dnsServers = dns,
        )
    }

    companion object {
        const val PREFIX = "l2tunnel://v1/connect"
        const val MAX_URI_BYTES = 16_384
        const val MAX_MEMBER_DER_BYTES = 256
        private val KNOWN_KEYS = setOf(
            "name", "peer", "cover", "noise", "peer_pub", "mtu", "path_mtu", "hs",
            "tun", "routes", "dns", "tune_repair", "tune_device_mtu", "tune_path_mtu",
            "layer", "adm", "key", "member", "psk",
        )

        fun decode(raw: String): ShareProfileUri {
            val trimmed = raw.trim()
            require(trimmed.isNotEmpty() && trimmed.length <= MAX_URI_BYTES) {
                "Share URI is empty or exceeds $MAX_URI_BYTES byte limit"
            }
            require(trimmed.all { it.code in 0x20..0x7E }) { "Share URI must be printable ASCII" }
            val hashIdx = trimmed.indexOf('#')
            val withoutFrag = if (hashIdx >= 0) trimmed.substring(0, hashIdx) else trimmed
            val fragment = if (hashIdx >= 0) percentDecode(trimmed.substring(hashIdx + 1)) else null
            val qIdx = withoutFrag.indexOf('?')
            require(qIdx > 0) { "Share URI missing query parameters" }
            val head = withoutFrag.substring(0, qIdx)
            require(head.equals(PREFIX, ignoreCase = true)) {
                "Unsupported share URI prefix (expected $PREFIX?...)"
            }
            val query = withoutFrag.substring(qIdx + 1)
            val map = LinkedHashMap<String, String>()
            for (pair in query.split('&')) {
                if (pair.isEmpty()) continue
                val eq = pair.indexOf('=')
                require(eq > 0) { "Malformed query parameter: $pair" }
                val key = pair.substring(0, eq).lowercase()
                val value = percentDecode(pair.substring(eq + 1))
                require(key in KNOWN_KEYS) { "Unknown query parameter: $key" }
                require(!map.containsKey(key)) { "Duplicate query parameter: $key" }
                map[key] = value
            }
            val layer = map["layer"]
            if (layer != null && !layer.equals("tun", ignoreCase = true)) {
                throw UnsupportedLayerException(
                    "layer=\"$layer\" is unsupported on Android VpnService (TUN L3 only)",
                )
            }
            val peer = map["peer"] ?: throw IllegalArgumentException("Missing required peer=host:port")
            val name = (map["name"] ?: fragment)?.trim()?.ifEmpty { null }
            val cover = map["cover"] ?: "quic-like"
            val noise = map["noise"] ?: "ik"
            val peerPub = map["peer_pub"]?.let { ProfileStore.parseHex32(it) }
            val tunMtu = map["mtu"]?.toIntOrNull() ?: if (map.containsKey("mtu")) {
                throw IllegalArgumentException("Invalid mtu")
            } else {
                1500
            }
            val pathMtu = map["path_mtu"]?.toIntOrNull() ?: if (map.containsKey("path_mtu")) {
                throw IllegalArgumentException("Invalid path_mtu")
            } else {
                1500
            }
            val hs = map["hs"]?.toIntOrNull() ?: if (map.containsKey("hs")) {
                throw IllegalArgumentException("Invalid hs")
            } else {
                30
            }
            val tun = map["tun"]?.trim()?.ifEmpty { null }
            val routes = map["routes"]
                ?.split(',')
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?: emptyList()
            val dns = map["dns"]
                ?.split(',')
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?: emptyList()
            val tuneRepair = map["tune_repair"]?.trim()?.ifEmpty { null }
            val tuneDeviceMtu = map["tune_device_mtu"]?.trim()?.ifEmpty { null }
            val tunePathMtu = map["tune_path_mtu"]?.trim()?.ifEmpty { null }
            val secrets = ShareSecrets(
                admission = map["adm"]?.let { ProfileStore.parseHex32(it) },
                noisePrivate = map["key"]?.let { ProfileStore.parseHex32(it) },
                memberPk8 = map["member"]?.let { base64UrlDecode(it) },
                noisePsk = map["psk"]?.let { ProfileStore.parseHex32(it) },
            )
            val parsed = ShareProfileUri(
                name = name,
                peer = peer,
                cover = cover,
                noise = noise,
                peerPub = peerPub,
                tunMtu = tunMtu,
                pathMtu = pathMtu,
                handshakeSeconds = hs,
                tun = tun,
                routes = routes,
                dns = dns,
                tuneRepair = tuneRepair,
                tuneDeviceMtu = tuneDeviceMtu,
                tunePathMtu = tunePathMtu,
                secrets = secrets,
            )
            parsed.validate()
            return parsed
        }

        private fun validateCidr(raw: String) {
            val parts = raw.split('/')
            require(parts.size == 2) { "Invalid CIDR: $raw" }
            val prefix = parts[1].toIntOrNull() ?: throw IllegalArgumentException("Invalid CIDR prefix: $raw")
            require(prefix in 0..128) { "CIDR prefix out of range: $raw" }
        }

        fun hexEncode(bytes: ByteArray): String =
            bytes.joinToString("") { "%02x".format(it) }

        private fun percentEncode(input: String): String {
            val sb = StringBuilder(input.length)
            for (b in input.toByteArray(StandardCharsets.UTF_8)) {
                val c = b.toInt() and 0xFF
                val unreserved = (c in 'a'.code..'z'.code) ||
                    (c in 'A'.code..'Z'.code) ||
                    (c in '0'.code..'9'.code) ||
                    c == '-'.code || c == '_'.code || c == '.'.code || c == '~'.code
                if (unreserved) {
                    sb.append(c.toChar())
                } else {
                    sb.append(String.format("%%%02X", c))
                }
            }
            return sb.toString()
        }

        private fun percentDecode(input: String): String {
            val out = ByteArrayOutputStream(input.length)
            var i = 0
            while (i < input.length) {
                when (val ch = input[i]) {
                    '%' -> {
                        require(i + 2 < input.length) { "Truncated percent-encoding" }
                        val hi = Character.digit(input[i + 1], 16)
                        val lo = Character.digit(input[i + 2], 16)
                        require(hi >= 0 && lo >= 0) { "Invalid percent-encoding" }
                        out.write((hi shl 4) or lo)
                        i += 3
                    }
                    '+' -> {
                        out.write(' '.code)
                        i += 1
                    }
                    else -> {
                        out.write(ch.code)
                        i += 1
                    }
                }
            }
            return String(out.toByteArray(), StandardCharsets.UTF_8)
        }

        private fun base64UrlEncode(bytes: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        private fun base64UrlDecode(text: String): ByteArray =
            Base64.getUrlDecoder().decode(text.trimEnd('='))
    }
}

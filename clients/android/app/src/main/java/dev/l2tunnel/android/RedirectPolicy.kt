package dev.l2tunnel.android

import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetAddress

/** Action applied when a destination IP matches a redirect rule. */
enum class RedirectAction(val wire: String) {
    TUNNEL("tunnel"),
    DIRECT("direct"),
    REJECT("reject"),
    ;

    companion object {
        fun parse(raw: String?): RedirectAction = when (raw?.trim()?.lowercase()) {
            null, "", "tunnel", "vpn", "proxy" -> TUNNEL
            "direct", "bypass" -> DIRECT
            "reject", "drop", "block" -> REJECT
            else -> throw IllegalArgumentException("Unsupported redirect action: $raw")
        }
    }
}

/** Canonical masked IPv4 CIDR prefix (`network / prefix`). */
data class Ipv4Cidr(val network: Long, val prefix: Int) {
    init {
        require(prefix in 0..32) { "IPv4 prefix out of range: $prefix" }
    }

    val start: Long get() = network and mask(prefix)
    val end: Long get() = start or (mask(prefix).inv() and 0xFFFF_FFFFL)

    fun contains(ip: Long): Boolean = (ip and mask(prefix)) == start

    fun toCidrPair(): Pair<String, Int> = formatIpv4(start) to prefix

    override fun toString(): String = "${formatIpv4(start)}/$prefix"

    companion object {
        fun mask(prefix: Int): Long =
            if (prefix == 0) 0L else (0xFFFF_FFFFL shl (32 - prefix)) and 0xFFFF_FFFFL

        fun parseIp(text: String): Long? {
            val parts = text.trim().split('.')
            if (parts.size != 4) return null
            var acc = 0L
            for (p in parts) {
                val n = p.toIntOrNull() ?: return null
                if (n !in 0..255) return null
                acc = (acc shl 8) or n.toLong()
            }
            return acc
        }

        fun formatIpv4(v: Long): String =
            "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"

        fun parse(text: String): Ipv4Cidr? {
            val parts = text.trim().split('/')
            if (parts.size != 2) return null
            val ip = parseIp(parts[0]) ?: return null
            val pref = parts[1].toIntOrNull() ?: return null
            if (pref !in 0..32) return null
            return Ipv4Cidr(ip and mask(pref), pref)
        }
    }
}

/** Match condition for one ordered redirect rule (matching Rust `redirect_policy.rs`). */
sealed class RuleMatcher {
    data class Cidr(val cidr: String) : RuleMatcher()
    data class Asn(val asn: Int) : RuleMatcher()
    data class GeoIp(val country: String, val region: String? = null) : RuleMatcher()
    data class Continent(val continent: String) : RuleMatcher()
    data object PrivateLan : RuleMatcher()
    data object Default : RuleMatcher()

    fun label(): String = when (this) {
        is Cidr -> "CIDR:$cidr"
        is Asn -> "ASN:AS$asn"
        is GeoIp -> if (region.isNullOrBlank()) "GEOIP:${country.uppercase()}" else "GEOIP:${country.uppercase()}-${region.uppercase()}"
        is Continent -> "CONTINENT:${continent.uppercase()}"
        PrivateLan -> "PRIVATE/LAN"
        Default -> "DEFAULT"
    }

    fun toJson(): JSONObject = when (this) {
        is Cidr -> JSONObject().put("type", "cidr").put("cidr", cidr)
        is Asn -> JSONObject().put("type", "asn").put("asn", asn)
        is GeoIp -> JSONObject().put("type", "geo_ip").put("country", country.uppercase()).apply {
            if (!region.isNullOrBlank()) put("region", region.uppercase())
        }
        is Continent -> JSONObject().put("type", "continent").put("continent", continent.uppercase())
        PrivateLan -> JSONObject().put("type", "private_lan")
        Default -> JSONObject().put("type", "default")
    }

    companion object {
        fun fromJson(obj: JSONObject): RuleMatcher = when (val type = obj.optString("type")) {
            "cidr" -> Cidr(obj.getString("cidr").trim())
            "asn" -> Asn(obj.getInt("asn").also { require(it > 0) { "ASN must be > 0" } })
            "geo_ip" -> GeoIp(
                country = obj.getString("country").trim().uppercase(),
                region = obj.optString("region", "").trim().uppercase().ifEmpty { null },
            )
            "continent" -> Continent(obj.getString("continent").trim().uppercase())
            "private_lan" -> PrivateLan
            "default" -> Default
            else -> throw IllegalArgumentException("Unknown rule matcher type: $type")
        }

        fun parseShorthand(raw: String): RuleMatcher {
            val trimmed = raw.trim()
            val lower = trimmed.lowercase()
            return when {
                lower in setOf("lan", "private", "private_lan", "private/lan") -> PrivateLan
                lower in setOf("default", "any", "*") -> Default
                lower.startsWith("cidr:") -> {
                    val c = trimmed.substring(5).trim()
                    require(Ipv4Cidr.parse(c) != null) { "Invalid IPv4 CIDR: $c" }
                    Cidr(c)
                }
                lower.startsWith("asn:") -> {
                    val n = lower.removePrefix("asn:").trim().removePrefix("as").toIntOrNull()
                        ?: throw IllegalArgumentException("Invalid ASN: $trimmed")
                    require(n > 0) { "ASN must be > 0" }
                    Asn(n)
                }
                lower.startsWith("as") && lower.length > 2 && lower.substring(2).all { it.isDigit() } -> {
                    val n = lower.substring(2).toInt()
                    require(n > 0) { "ASN must be > 0" }
                    Asn(n)
                }
                lower.startsWith("geoip:") || lower.startsWith("country:") -> {
                    val rest = trimmed.substringAfter(':').trim().uppercase()
                    val (cc, reg) = if ('-' in rest) {
                        rest.substringBefore('-') to rest.substringAfter('-').ifEmpty { null }
                    } else {
                        rest to null
                    }
                    require(cc.length == 2 && cc.all { it.isLetter() }) { "GeoIP country must be 2 letters (e.g. CN, US, JP)" }
                    GeoIp(cc, reg)
                }
                lower.startsWith("continent:") -> {
                    val c = trimmed.substringAfter(':').trim().uppercase()
                    require(c in setOf("AF", "AN", "AS", "EU", "NA", "OC", "SA")) { "Invalid continent: $c" }
                    Continent(c)
                }
                '/' in trimmed -> {
                    require(Ipv4Cidr.parse(trimmed) != null) { "Invalid IPv4 CIDR: $trimmed" }
                    Cidr(trimmed)
                }
                else -> throw IllegalArgumentException("Use cidr:IP/LEN, asn:N, geoip:CC, continent:CODE, or lan")
            }
        }
    }
}

data class RedirectRule(
    val id: String,
    val enabled: Boolean = true,
    val matcher: RuleMatcher,
    val action: RedirectAction,
    val comment: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id)
        .put("enabled", enabled)
        .put("matcher", matcher.toJson())
        .put("action", action.wire)
        .apply { if (!comment.isNullOrBlank()) put("comment", comment) }

    companion object {
        fun fromJson(obj: JSONObject): RedirectRule = RedirectRule(
            id = obj.optString("id", "rule"),
            enabled = obj.optBoolean("enabled", true),
            matcher = RuleMatcher.fromJson(obj.getJSONObject("matcher")),
            action = RedirectAction.parse(obj.optString("action", "tunnel")),
            comment = obj.optString("comment", "").ifEmpty { null },
        )
    }
}

data class IpGeoAsnInfo(
    val matchedPrefix: String,
    val country: String,
    val region: String?,
    val continent: String,
    val asn: Int,
    val org: String,
)

data class PolicyDecision(
    val ip: String,
    val action: RedirectAction,
    val matchedRuleId: String,
    val matchedBy: String,
    val geo: IpGeoAsnInfo?,
)

data class CompiledIpv4Routes(
    val includeRoutes: List<Pair<String, Int>>,
    val excludeRoutes: List<Pair<String, Int>>,
    val activeRules: Int,
    val expandedPrefixes: Int,
)

/** Offline GeoIP + ASN prefix database mirroring Rust `IpGeoAsnDatabase::builtin()`. */
class IpGeoAsnDatabase(private val records: MutableList<Record> = mutableListOf()) {
    data class Record(
        val cidr: Ipv4Cidr,
        val country: String,
        val region: String?,
        val continent: String,
        val asn: Int,
        val org: String,
    )

    val size: Int get() = records.size

    fun lookup(ipText: String): IpGeoAsnInfo? {
        val ip = Ipv4Cidr.parseIp(ipText) ?: return null
        var best: Record? = null
        for (rec in records) {
            if (rec.cidr.contains(ip) && (best == null || rec.cidr.prefix >= best.cidr.prefix)) {
                best = rec
            }
        }
        return best?.let {
            IpGeoAsnInfo(
                matchedPrefix = it.cidr.toString(),
                country = it.country,
                region = it.region,
                continent = it.continent,
                asn = it.asn,
                org = it.org,
            )
        }
    }

    fun prefixesFor(matcher: RuleMatcher): List<Ipv4Cidr> = when (matcher) {
        is RuleMatcher.Cidr -> listOfNotNull(Ipv4Cidr.parse(matcher.cidr))
        is RuleMatcher.Asn -> records.filter { it.asn == matcher.asn }.map { it.cidr }
        is RuleMatcher.GeoIp -> {
            val wantCc = matcher.country.uppercase()
            val wantReg = matcher.region?.uppercase()
            records.filter {
                it.country == wantCc && (wantReg == null || it.region == wantReg)
            }.map { it.cidr }
        }
        is RuleMatcher.Continent -> {
            val want = matcher.continent.uppercase()
            records.filter { it.continent == want }.map { it.cidr }
        }
        RuleMatcher.PrivateLan -> PRIVATE_LAN_V4
        RuleMatcher.Default -> listOf(Ipv4Cidr(0L, 0))
    }

    fun loadCsv(text: String): Int {
        var added = 0
        text.lineSequence().forEachIndexed { idx, raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEachIndexed
            if (line.lowercase().startsWith("cidr,")) return@forEachIndexed
            val parts = line.split(',', limit = 6).map { it.trim() }
            if (parts.size < 2) return@forEachIndexed
            val cidr = Ipv4Cidr.parse(parts[0]) ?: return@forEachIndexed
            val cc = parts.getOrNull(1)?.uppercase()?.ifEmpty { "ZZ" } ?: "ZZ"
            val reg = parts.getOrNull(2)?.uppercase()?.ifEmpty { null }
            val cont = parts.getOrNull(3)?.uppercase()?.ifEmpty { "ZZ" } ?: "ZZ"
            val asn = parts.getOrNull(4)?.removePrefix("AS")?.removePrefix("as")?.toIntOrNull() ?: 0
            val org = parts.getOrNull(5) ?: ""
            records.add(Record(cidr, cc, reg, cont, asn, org))
            added += 1
        }
        return added
    }

    companion object {
        val PRIVATE_LAN_V4: List<Ipv4Cidr> = listOf(
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/4",
        ).mapNotNull { Ipv4Cidr.parse(it) }

        fun isPrivateLan(ipText: String): Boolean {
            val ip = Ipv4Cidr.parseIp(ipText) ?: return false
            return PRIVATE_LAN_V4.any { it.contains(ip) }
        }

        fun builtin(): IpGeoAsnDatabase {
            val db = IpGeoAsnDatabase()
            val seed = listOf(
                arrayOf("10.0.0.0/8", "ZZ", "", "ZZ", "0", "Private-LAN RFC1918"),
                arrayOf("100.64.0.0/10", "ZZ", "", "ZZ", "0", "Shared-CGNAT RFC6598"),
                arrayOf("127.0.0.0/8", "ZZ", "", "ZZ", "0", "Loopback"),
                arrayOf("169.254.0.0/16", "ZZ", "", "ZZ", "0", "Link-Local"),
                arrayOf("172.16.0.0/12", "ZZ", "", "ZZ", "0", "Private-LAN RFC1918"),
                arrayOf("192.168.0.0/16", "ZZ", "", "ZZ", "0", "Private-LAN RFC1918"),
                // Cloudflare (AS13335)
                arrayOf("1.1.1.0/24", "AU", "SYD", "OC", "13335", "Cloudflare Inc."),
                arrayOf("1.0.0.0/24", "AU", "SYD", "OC", "13335", "Cloudflare Inc."),
                arrayOf("104.16.0.0/13", "US", "CA", "NA", "13335", "Cloudflare Inc."),
                arrayOf("104.24.0.0/14", "US", "CA", "NA", "13335", "Cloudflare Inc."),
                arrayOf("172.64.0.0/13", "US", "CA", "NA", "13335", "Cloudflare Inc."),
                // Google (AS15169)
                arrayOf("8.8.8.0/24", "US", "CA", "NA", "15169", "Google LLC"),
                arrayOf("8.8.4.0/24", "US", "CA", "NA", "15169", "Google LLC"),
                arrayOf("142.250.0.0/15", "US", "CA", "NA", "15169", "Google LLC"),
                arrayOf("172.217.0.0/16", "US", "CA", "NA", "15169", "Google LLC"),
                arrayOf("216.58.192.0/19", "US", "CA", "NA", "15169", "Google LLC"),
                // AWS (AS16509) / Microsoft (AS8075) / Meta (AS32934) / Fastly (AS54113) / GitHub (AS36459)
                arrayOf("3.0.0.0/9", "US", "VA", "NA", "16509", "Amazon.com Inc."),
                arrayOf("13.32.0.0/15", "US", "WA", "NA", "16509", "Amazon CloudFront"),
                arrayOf("52.0.0.0/11", "US", "VA", "NA", "16509", "Amazon.com Inc."),
                arrayOf("54.144.0.0/12", "US", "VA", "NA", "16509", "Amazon.com Inc."),
                arrayOf("13.64.0.0/11", "US", "WA", "NA", "8075", "Microsoft Corporation"),
                arrayOf("20.0.0.0/11", "US", "WA", "NA", "8075", "Microsoft Azure"),
                arrayOf("40.64.0.0/10", "US", "WA", "NA", "8075", "Microsoft Corporation"),
                arrayOf("31.13.24.0/21", "US", "CA", "NA", "32934", "Meta Platforms Inc."),
                arrayOf("157.240.0.0/16", "US", "CA", "NA", "32934", "Meta Platforms Inc."),
                arrayOf("151.101.0.0/16", "US", "CA", "NA", "54113", "Fastly Inc."),
                arrayOf("140.82.112.0/20", "US", "CA", "NA", "36459", "GitHub Inc."),
                // China Telecom (AS4134), China Unicom (AS4837), China Mobile (AS9808), Alibaba, Tencent
                arrayOf("114.114.114.0/24", "CN", "JS", "AS", "4134", "ChinaNet Backbone"),
                arrayOf("61.128.0.0/10", "CN", "BJ", "AS", "4134", "ChinaNet Backbone"),
                arrayOf("180.76.0.0/16", "CN", "BJ", "AS", "4134", "ChinaNet / Baidu"),
                arrayOf("183.0.0.0/10", "CN", "GD", "AS", "4134", "ChinaNet Guangdong"),
                arrayOf("202.96.0.0/12", "CN", "SH", "AS", "4134", "ChinaNet Backbone"),
                arrayOf("222.64.0.0/11", "CN", "SH", "AS", "4134", "ChinaNet Shanghai"),
                arrayOf("111.160.0.0/11", "CN", "TJ", "AS", "4837", "China169 Backbone"),
                arrayOf("123.125.0.0/16", "CN", "BJ", "AS", "4837", "China169 Beijing"),
                arrayOf("218.56.0.0/13", "CN", "SD", "AS", "4837", "China169 Shandong"),
                arrayOf("221.0.0.0/11", "CN", "BJ", "AS", "4837", "China169 Backbone"),
                arrayOf("111.0.0.0/10", "CN", "BJ", "AS", "9808", "China Mobile Communications"),
                arrayOf("120.192.0.0/10", "CN", "GD", "AS", "9808", "China Mobile Communications"),
                arrayOf("223.5.5.0/24", "CN", "ZJ", "AS", "37963", "Alibaba AliDNS"),
                arrayOf("223.6.6.0/24", "CN", "ZJ", "AS", "37963", "Alibaba AliDNS"),
                arrayOf("47.88.0.0/13", "SG", "SG", "AS", "45102", "Alibaba US/SG Cloud"),
                arrayOf("106.11.0.0/16", "CN", "ZJ", "AS", "37963", "Alibaba Cloud China"),
                arrayOf("119.29.0.0/16", "CN", "GD", "AS", "45090", "Tencent Cloud DNSPod"),
                arrayOf("43.128.0.0/11", "SG", "SG", "AS", "132203", "Tencent Cloud Global"),
                // JP / HK / TW / KR / SG / EU / NA / AU
                arrayOf("106.128.0.0/10", "JP", "TYO", "AS", "2516", "KDDI Corporation"),
                arrayOf("126.0.0.0/9", "JP", "TYO", "AS", "17676", "SoftBank BB Corp."),
                arrayOf("129.250.0.0/16", "JP", "TYO", "AS", "2914", "NTT America/Global"),
                arrayOf("203.198.0.0/15", "HK", "HK", "AS", "4760", "HKT Limited"),
                arrayOf("168.95.0.0/16", "TW", "TPE", "AS", "3462", "Chunghwa Telecom HiNet"),
                arrayOf("112.160.0.0/11", "KR", "SEL", "AS", "4766", "Korea Telecom"),
                arrayOf("165.21.0.0/16", "SG", "SG", "AS", "7473", "Singapore Telecom"),
                arrayOf("80.128.0.0/11", "DE", "FRA", "EU", "3320", "Deutsche Telekom AG"),
                arrayOf("116.202.0.0/15", "DE", "FSN", "EU", "24940", "Hetzner Online GmbH"),
                arrayOf("81.128.0.0/10", "GB", "LON", "EU", "2856", "British Telecommunications"),
                arrayOf("51.38.0.0/16", "FR", "PAR", "EU", "16276", "OVH SAS"),
                arrayOf("185.199.108.0/22", "NL", "AMS", "EU", "54113", "Fastly / GitHub Pages EU"),
                arrayOf("73.0.0.0/8", "US", "PA", "NA", "7922", "Comcast Cable Communications"),
                arrayOf("99.0.0.0/10", "US", "TX", "NA", "7018", "AT&T Services Inc."),
                arrayOf("1.128.0.0/11", "AU", "SYD", "OC", "1221", "Telstra Corporation"),
            )
            for (row in seed) {
                val cidr = Ipv4Cidr.parse(row[0]) ?: continue
                db.records.add(
                    Record(
                        cidr = cidr,
                        country = row[1],
                        region = row[2].ifEmpty { null },
                        continent = row[3],
                        asn = row[4].toInt(),
                        org = row[5],
                    ),
                )
            }
            return db
        }
    }
}

/** Ordered redirect / traffic routing policy stored inside `android_vpn.json`. */
data class RedirectPolicy(
    val enabled: Boolean = false,
    val defaultAction: RedirectAction = RedirectAction.TUNNEL,
    val bypassPeerEndpoint: Boolean = true,
    val rules: List<RedirectRule> = emptyList(),
) {
    fun evaluate(ipText: String, db: IpGeoAsnDatabase = IpGeoAsnDatabase.builtin()): PolicyDecision {
        val geo = db.lookup(ipText)
        val parsedIp = Ipv4Cidr.parseIp(ipText)
        for (rule in rules) {
            if (!rule.enabled) continue
            val matched = when (val m = rule.matcher) {
                is RuleMatcher.Cidr -> parsedIp != null && (Ipv4Cidr.parse(m.cidr)?.contains(parsedIp) == true)
                is RuleMatcher.Asn -> geo?.asn == m.asn
                is RuleMatcher.GeoIp -> geo != null &&
                    geo.country.equals(m.country, ignoreCase = true) &&
                    (m.region.isNullOrBlank() || geo.region.equals(m.region, ignoreCase = true))
                is RuleMatcher.Continent -> geo != null && geo.continent.equals(m.continent, ignoreCase = true)
                RuleMatcher.PrivateLan -> IpGeoAsnDatabase.isPrivateLan(ipText)
                RuleMatcher.Default -> true
            }
            if (matched) {
                return PolicyDecision(ipText, rule.action, rule.id, rule.matcher.label(), geo)
            }
        }
        return PolicyDecision(ipText, defaultAction, "default_action", "DEFAULT(${defaultAction.wire})", geo)
    }

    /**
     * Compiles exact minimal non-overlapping IPv4 TUN routes via interval subtraction,
     * always excluding `peerHost` if it is a literal IPv4 address (anti-loop).
     */
    fun compileIpv4Routes(
        db: IpGeoAsnDatabase = IpGeoAsnDatabase.builtin(),
        peerHost: String? = null,
        alwaysIncludeCidrs: List<Pair<String, Int>> = emptyList(),
    ): CompiledIpv4Routes {
        var tunnelRanges = if (defaultAction == RedirectAction.TUNNEL) {
            mutableListOf(0L to 0xFFFF_FFFFL)
        } else {
            mutableListOf()
        }
        var excludeRanges = mutableListOf<Pair<Long, Long>>()
        var activeCount = 0
        var expanded = 0

        for (rule in rules.asReversed()) {
            if (!rule.enabled) continue
            activeCount += 1
            val prefixes = db.prefixesFor(rule.matcher)
            expanded += prefixes.size
            val ranges = prefixes.map { it.start to it.end }
            when (rule.action) {
                RedirectAction.TUNNEL -> {
                    tunnelRanges = mergeRanges(tunnelRanges + ranges)
                    excludeRanges = subtractRanges(excludeRanges, ranges)
                }
                RedirectAction.DIRECT -> {
                    tunnelRanges = subtractRanges(tunnelRanges, ranges)
                    excludeRanges = mergeRanges(excludeRanges + ranges)
                }
                RedirectAction.REJECT -> {
                    tunnelRanges = subtractRanges(tunnelRanges, ranges)
                }
            }
        }

        // Preserve any explicit profile tunnel-subnet routes (e.g. 192.168.236.0/30)
        // when the user explicitly listed them, even if PrivateLan is bypassed.
        val explicitRanges = alwaysIncludeCidrs.mapNotNull { (ip, pref) ->
            if (pref == 0) null else Ipv4Cidr.parse("$ip/$pref")?.let { it.start to it.end }
        }
        if (explicitRanges.isNotEmpty()) {
            tunnelRanges = mergeRanges(tunnelRanges + explicitRanges)
            excludeRanges = subtractRanges(excludeRanges, explicitRanges)
        }

        if (bypassPeerEndpoint && !peerHost.isNullOrBlank()) {
            val hostOnly = peerHost.substringBefore(':')
            val peerIp = Ipv4Cidr.parseIp(hostOnly) ?: try {
                (InetAddress.getByName(hostOnly) as? Inet4Address)?.hostAddress?.let { Ipv4Cidr.parseIp(it) }
            } catch (_: Exception) {
                null
            }
            if (peerIp != null) {
                val peerRange = listOf(peerIp to peerIp)
                tunnelRanges = subtractRanges(tunnelRanges, peerRange)
                excludeRanges = mergeRanges(excludeRanges + peerRange)
            }
        }

        val incCidrs = rangesToCidrs(tunnelRanges).map { it.toCidrPair() }
        val excCidrs = rangesToCidrs(excludeRanges).map { it.toCidrPair() }
        return CompiledIpv4Routes(incCidrs, excCidrs, activeCount, expanded)
    }

    fun toJson(): JSONObject {
        val arr = JSONArray()
        rules.forEach { arr.put(it.toJson()) }
        return JSONObject()
            .put("version", 1)
            .put("enabled", enabled)
            .put("default_action", defaultAction.wire)
            .put("bypass_peer_endpoint", bypassPeerEndpoint)
            .put("rules", arr)
    }

    companion object {
        val PRESET_NAMES: List<Pair<String, String>> = listOf(
            "global-bypass-lan" to "Global Tunnel (Bypass LAN)",
            "bypass-cn-and-lan" to "Bypass CN GeoIP + LAN",
            "bypass-cn-asns" to "Bypass Major CN ASNs + LAN",
            "tunnel-us-eu-only" to "Tunnel US / EU / CF / Google Only",
            "tunnel-cloudflare-google" to "Tunnel AS13335 + AS15169 Only",
        )

        fun preset(name: String): RedirectPolicy = when (name) {
            "global-bypass-lan" -> RedirectPolicy(
                enabled = true,
                defaultAction = RedirectAction.TUNNEL,
                rules = listOf(
                    RedirectRule("bypass-lan", true, RuleMatcher.PrivateLan, RedirectAction.DIRECT, "Local LAN/CGNAT direct"),
                ),
            )
            "bypass-cn-and-lan" -> RedirectPolicy(
                enabled = true,
                defaultAction = RedirectAction.TUNNEL,
                rules = listOf(
                    RedirectRule("bypass-lan", true, RuleMatcher.PrivateLan, RedirectAction.DIRECT, "Local LAN direct"),
                    RedirectRule("bypass-geoip-cn", true, RuleMatcher.GeoIp("CN"), RedirectAction.DIRECT, "Mainland China IP location"),
                ),
            )
            "bypass-cn-asns" -> RedirectPolicy(
                enabled = true,
                defaultAction = RedirectAction.TUNNEL,
                rules = listOf(
                    RedirectRule("bypass-lan", true, RuleMatcher.PrivateLan, RedirectAction.DIRECT, "Local LAN direct"),
                    RedirectRule("bypass-as4134", true, RuleMatcher.Asn(4134), RedirectAction.DIRECT, "ChinaNet"),
                    RedirectRule("bypass-as4837", true, RuleMatcher.Asn(4837), RedirectAction.DIRECT, "China169"),
                    RedirectRule("bypass-as9808", true, RuleMatcher.Asn(9808), RedirectAction.DIRECT, "China Mobile"),
                    RedirectRule("bypass-as37963", true, RuleMatcher.Asn(37963), RedirectAction.DIRECT, "Alibaba CN"),
                    RedirectRule("bypass-as45090", true, RuleMatcher.Asn(45090), RedirectAction.DIRECT, "Tencent CN"),
                ),
            )
            "tunnel-us-eu-only" -> RedirectPolicy(
                enabled = true,
                defaultAction = RedirectAction.DIRECT,
                rules = listOf(
                    RedirectRule("bypass-lan", true, RuleMatcher.PrivateLan, RedirectAction.DIRECT, "Local LAN direct"),
                    RedirectRule("tunnel-as13335", true, RuleMatcher.Asn(13335), RedirectAction.TUNNEL, "Cloudflare"),
                    RedirectRule("tunnel-as15169", true, RuleMatcher.Asn(15169), RedirectAction.TUNNEL, "Google"),
                    RedirectRule("tunnel-geoip-us", true, RuleMatcher.GeoIp("US"), RedirectAction.TUNNEL, "United States"),
                    RedirectRule("tunnel-continent-eu", true, RuleMatcher.Continent("EU"), RedirectAction.TUNNEL, "Europe"),
                ),
            )
            "tunnel-cloudflare-google" -> RedirectPolicy(
                enabled = true,
                defaultAction = RedirectAction.DIRECT,
                rules = listOf(
                    RedirectRule("tunnel-cf", true, RuleMatcher.Asn(13335), RedirectAction.TUNNEL, "Cloudflare"),
                    RedirectRule("tunnel-gg", true, RuleMatcher.Asn(15169), RedirectAction.TUNNEL, "Google"),
                ),
            )
            else -> RedirectPolicy(enabled = false)
        }

        fun fromJson(obj: JSONObject): RedirectPolicy {
            val rulesArr = obj.optJSONArray("rules")
            val list = mutableListOf<RedirectRule>()
            if (rulesArr != null) {
                for (i in 0 until rulesArr.length()) {
                    list.add(RedirectRule.fromJson(rulesArr.getJSONObject(i)))
                }
            }
            return RedirectPolicy(
                enabled = obj.optBoolean("enabled", false),
                defaultAction = RedirectAction.parse(obj.optString("default_action", "tunnel")),
                bypassPeerEndpoint = obj.optBoolean("bypass_peer_endpoint", true),
                rules = list,
            )
        }

        private fun mergeRanges(input: List<Pair<Long, Long>>): MutableList<Pair<Long, Long>> {
            if (input.isEmpty()) return mutableListOf()
            val sorted = input.sortedWith(compareBy<Pair<Long, Long>> { it.first }.thenBy { it.second })
            val out = mutableListOf<Pair<Long, Long>>()
            for ((s, e) in sorted) {
                if (out.isNotEmpty() && s <= out.last().second + 1L) {
                    val last = out.removeAt(out.lastIndex)
                    out.add(last.first to maxOf(last.second, e))
                } else {
                    out.add(s to e)
                }
            }
            return out
        }

        private fun subtractRanges(
            base: List<Pair<Long, Long>>,
            remove: List<Pair<Long, Long>>,
        ): MutableList<Pair<Long, Long>> {
            if (base.isEmpty() || remove.isEmpty()) return base.toMutableList()
            val rem = mergeRanges(remove)
            var current = mergeRanges(base)
            for ((rs, re) in rem) {
                val next = mutableListOf<Pair<Long, Long>>()
                for ((s, e) in current) {
                    if (re < s || rs > e) {
                        next.add(s to e)
                    } else {
                        if (rs > s) next.add(s to (rs - 1L))
                        if (re < e) next.add((re + 1L) to e)
                    }
                }
                current = next
            }
            return current
        }

        private fun rangesToCidrs(ranges: List<Pair<Long, Long>>): List<Ipv4Cidr> {
            val out = mutableListOf<Ipv4Cidr>()
            for ((start, end) in ranges) {
                var cur = start
                while (cur <= end) {
                    val maxAlign = if (cur == 0L) 32 else java.lang.Long.numberOfTrailingZeros(cur).coerceAtMost(32)
                    val remaining = end - cur + 1L
                    var bits = maxAlign
                    while (bits > 0 && (1L shl bits) > remaining) {
                        bits -= 1
                    }
                    out.add(Ipv4Cidr(cur, 32 - bits))
                    cur += 1L shl bits
                }
            }
            return out
        }
    }
}

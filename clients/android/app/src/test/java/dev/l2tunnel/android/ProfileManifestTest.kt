package dev.l2tunnel.android

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

class ProfileManifestTest {
    private val validClient = """
        {
          "version": 1,
          "carrier": "udp",
          "cover": "quic-like",
          "udp_bind": "0.0.0.0:0",
          "udp_peer": "198.51.100.10:24461",
          "path_mtu": 1400,
          "tun_mtu": 1340,
          "noise_profile": "ik",
          "handshake_seconds": 10,
          "layer": "tun",
          "tune_repair": "off,1/8,1/4"
        }
    """.trimIndent()

    @Test
    fun parsesValidAndroidTunProfileWithCustomRoutes() {
        val vpn = """
            {
              "tun_address": "10.235.0.2",
              "tun_prefix": 30,
              "routes": ["0.0.0.0/0", "10.0.0.0/8"],
              "dns": ["1.1.1.1", "8.8.8.8"]
            }
        """.trimIndent()
        val parsed = AndroidVpnProfile.parse(File("/tmp/demo"), validClient, vpn)
        assertEquals("0.0.0.0:0", parsed.udpBind)
        assertEquals("198.51.100.10:24461", parsed.udpPeer)
        assertEquals(1340, parsed.tunMtu)
        assertEquals("10.235.0.2", parsed.tunAddress)
        assertEquals(30, parsed.tunPrefixLength)
        assertEquals(listOf("0.0.0.0" to 0, "10.0.0.0" to 8), parsed.routes)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), parsed.dnsServers)
    }

    @Test(expected = UnsupportedLayerException::class)
    fun refusesTapLayerExplicitly() {
        val tapClient = validClient.replace("\"layer\": \"tun\"", "\"layer\": \"tap\"")
        AndroidVpnProfile.parse(File("/tmp/demo"), tapClient)
    }

    @Test(expected = UnsupportedLayerException::class)
    fun refusesVxlanAttachmentExplicitly() {
        val vxlanClient = validClient.replace("\"layer\": \"tun\"", "\"vxlan_vni\": 100")
        AndroidVpnProfile.parse(File("/tmp/demo"), vxlanClient)
    }
}

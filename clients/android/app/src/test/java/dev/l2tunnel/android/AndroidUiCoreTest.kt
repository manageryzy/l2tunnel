package dev.l2tunnel.android

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class AndroidUiCoreTest {
    private class InMemoryAesKeyProvider : SecretKeyProvider {
        private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        override fun getOrCreateMasterKey(): SecretKey = key
    }

    private fun validClientJson(extra: String = ""): String =
        """
        {
          "version": 1,
          "carrier": "udp",
          "cover": "quic-like",
          "udp_bind": "0.0.0.0:0",
          "udp_peer": "192.168.210.108:24461",
          "path_mtu": 1500,
          "tun_mtu": 1500,
          "noise_profile": "ik",
          "handshake_seconds": 30,
          "layer": "tun"$extra
        }
        """.trimIndent()

    private fun buildZip(entries: Map<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zos ->
            for ((name, data) in entries) {
                zos.putNextEntry(ZipEntry(name))
                zos.write(data)
                zos.closeEntry()
            }
        }
        return out.toByteArray()
    }

    @Test
    fun keystoreEnvelopeEncryptsDecryptsRejectsTamperingAndScrubsEphemeralStaging() {
        val store = KeystoreSecretStore(InMemoryAesKeyProvider())
        val aad = KeystoreSecretStore.associatedDataFor("work", "noise-private.key")
        val secret = ByteArray(32) { (it * 7 + 3).toByte() }
        val sealed = store.encrypt(secret, aad)
        assertFalse(sealed.contentEquals(secret))
        assertArrayEquals(secret, store.decrypt(sealed, aad))

        // Flip a ciphertext byte -> AEAD authentication must fail.
        val tampered = sealed.copyOf()
        tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0xFF).toByte()
        try {
            store.decrypt(tampered, aad)
            fail("Tampered GCM blob must throw")
        } catch (_: Exception) {
        }

        // Wrong AAD (cross-profile swap) -> AEAD must fail.
        try {
            store.decrypt(sealed, KeystoreSecretStore.associatedDataFor("other", "noise-private.key"))
            fail("Mismatched profile AAD must throw")
        } catch (_: Exception) {
        }

        // Full profile materialization + scrub check
        val tmpRoot = Files.createTempDirectory("l2t-ks-test-").toFile()
        try {
            val profDir = File(tmpRoot, "work").apply { mkdirs() }
            File(profDir, "client.json").writeText(validClientJson())
            File(profDir, "common.json").writeText("{}")
            File(profDir, "noise-peer.pub").writeBytes(ByteArray(32) { 1 })
            store.writeEncryptedSecret(profDir, "noise-private.key", secret)
            store.writeEncryptedSecret(profDir, "member.pk8", ByteArray(48) { 2 })
            store.writeEncryptedSecret(profDir, "admission.key", ByteArray(32) { 3 })
            assertTrue(store.isKeystoreSealed(profDir))
            assertFalse(File(profDir, "noise-private.key").exists())

            val runtimeDir = File(tmpRoot, "runtime/run-1")
            store.materializeRuntimeDirectory(profDir, runtimeDir)
            assertArrayEquals(secret, File(runtimeDir, "noise-private.key").readBytes())

            KeystoreSecretStore.scrubDirectory(runtimeDir)
            assertFalse(runtimeDir.exists())
        } finally {
            tmpRoot.deleteRecursively()
        }
    }

    @Test
    fun zipImporterSealsSecretsRejectsTraversalAndRefusesTapVxlan() {
        val tmpRoot = Files.createTempDirectory("l2t-zip-test-").toFile()
        try {
            val secretStore = KeystoreSecretStore(InMemoryAesKeyProvider())
            val profileStore = ProfileStore(File(tmpRoot, "profiles"), secretStore = secretStore)

            val goodZip = buildZip(
                mapOf(
                    "bundle/client.json" to validClientJson().toByteArray(),
                    "bundle/common.json" to "{}".toByteArray(),
                    "bundle/noise-peer.pub" to ByteArray(32) { 5 },
                    "bundle/noise-private.key" to ByteArray(32) { 6 },
                    "bundle/member.pk8" to ByteArray(48) { 7 },
                    "bundle/admission.key" to ByteArray(32) { 8 },
                ),
            )
            val imported = profileStore.importZipBundle("Office VPN", ByteArrayInputStream(goodZip))
            assertEquals("office-vpn", imported.id)
            assertTrue(imported.isValid)
            assertTrue(imported.keystoreSealed)
            assertFalse(File(imported.directory, "noise-private.key").exists())
            assertTrue(File(imported.directory, "noise-private.key.enc").isFile)

            // Reject path traversal
            val evilZip = buildZip(
                mapOf("../escape.txt" to "bad".toByteArray()),
            )
            try {
                ProfileZipImporter.readValidatedBundle(ByteArrayInputStream(evilZip))
                fail("Path traversal archive must be rejected")
            } catch (_: IOException) {
            }

            // Explicitly refuse TAP/VXLAN archive
            val tapZip = buildZip(
                mapOf(
                    "client.json" to validClientJson().replace("\"tun\"", "\"tap\"").toByteArray(),
                    "common.json" to "{}".toByteArray(),
                    "noise-peer.pub" to ByteArray(32) { 1 },
                    "noise-private.key" to ByteArray(32) { 2 },
                    "member.pk8" to ByteArray(48) { 3 },
                    "admission.key" to ByteArray(32) { 4 },
                ),
            )
            try {
                ProfileZipImporter.readValidatedBundle(ByteArrayInputStream(tapZip))
                fail("TAP layer archive must throw UnsupportedLayerException")
            } catch (_: UnsupportedLayerException) {
            }
        } finally {
            tmpRoot.deleteRecursively()
        }
    }

    @Test
    fun splitTunnelAlwaysPreventsSelfLoop() {
        val selfPkg = "dev.l2tunnel.android"
        val base = AndroidVpnProfile.parse(
            File("p"),
            validClientJson(),
            """
            {
              "tun_address": "10.236.0.2",
              "tun_prefix": 30,
              "routes": ["0.0.0.0/0"],
              "dns": [],
              "split_tunnel_mode": "include",
              "split_tunnel_apps": ["com.android.chromium", "dev.l2tunnel.android"]
            }
            """.trimIndent(),
        )
        val (allowed, disallowed) = base.resolveSplitTunnelPackages(selfPkg)
        assertEquals(listOf("com.android.chromium"), allowed)
        assertTrue(disallowed.isEmpty())

        val exclude = base.copy(splitTunnelMode = SplitTunnelMode.EXCLUDE)
        val (exAllowed, exDisallowed) = exclude.resolveSplitTunnelPackages(selfPkg)
        assertTrue(exAllowed.isEmpty())
        assertTrue(selfPkg in exDisallowed)
        assertTrue("com.android.chromium" in exDisallowed)
    }

    @Test
    fun diagnosticsRedactsEndpointsAndNeverLeaksSecrets() {
        val report = DiagnosticsExporter.buildReportJson(
            appVersion = "0.2.0",
            state = VpnUiState(
                running = true,
                phase = "connected",
                headline = "Connected",
                peer = "192.168.210.108:24461",
                cover = "quic-like",
                events = listOf(UiEventEntry(1000L, "service", "connected to 192.168.210.108:24461")),
            ),
            activeProfile = null,
            redactEndpoints = true,
        )
        assertFalse(report.contains("192.168.210.108"))
        assertTrue(report.contains("<redacted-ip>"))
        val parsed = JSONObject(report)
        assertEquals("l2tunnel-android-diagnostics-v1", parsed.getString("schema"))
        assertFalse(parsed.getJSONObject("capabilities").getBoolean("tap_supported"))
    }

    @Test
    fun localApiV5ParsesTuningTunnelTestMetersAndEvents() {
        val tuningReply = JSONObject(
            """
            {
              "version": 5, "ok": true, "code": "ok",
              "tuning": {
                "live": true,
                "current": {"repair": "1/4", "device_mtu": 1500, "path_mtu": 1500},
                "repair": ["off", "1/8", "1/4"],
                "device_mtu": [1400, 1500],
                "path_mtu": [1500],
                "entries": [
                  {"repair": "off", "device_mtu": 1500, "path_mtu": 1500},
                  {"repair": "1/4", "device_mtu": 1500, "path_mtu": 1500}
                ]
              }
            }
            """.trimIndent(),
        )
        val tuning = LocalApiV5Codec.parseTuning(tuningReply)
        assertNotNull(tuning)
        assertEquals("1/4", tuning?.current?.repair)
        assertEquals(listOf("off", "1/8", "1/4"), tuning?.repairChoices)

        val testReply = JSONObject(
            """
            {
              "version": 5, "ok": true, "code": "ok",
              "test": {
                "test": {
                  "id": 3, "kind": "ping", "state": "completed",
                  "elapsed_ms": 620, "bytes": 0, "bits_per_second": 0, "samples": [],
                  "ping": {"sent": 5, "received": 5, "min_us": 4200, "avg_us": 4900, "max_us": 5600, "rtts_us": [4200, 4900, 5600, 4800, 5000]}
                }
              }
            }
            """.trimIndent(),
        )
        val test = LocalApiV5Codec.parseTunnelTest(testReply)
        assertNotNull(test)
        assertEquals(5, test?.ping?.received)
        assertEquals(4900L, test?.ping?.avgUs)

        val metersReply = JSONObject(
            """
            {
              "version": 5, "ok": true, "code": "ok",
              "meters": {
                "side": "local", "generation": 1, "sampled_ms": 500,
                "entries": [{"path": "wire.tx.packets", "value": 42}]
              }
            }
            """.trimIndent(),
        )
        val meters = LocalApiV5Codec.parseMeters(metersReply)
        assertEquals(1, meters.size)
        assertEquals("wire.tx.packets", meters[0].path)
        assertEquals(42L, meters[0].value)

        val eventsReply = JSONObject(
            """
            {
              "version": 5, "ok": true, "code": "ok",
              "events": {
                "next": 9, "gap": false,
                "events": [{"sequence": 8, "event": {"type": "lifecycle", "phase": "connected"}}]
              }
            }
            """.trimIndent(),
        )
        val ev = LocalApiV5Codec.parseEvents(eventsReply)
        assertEquals(9L, ev?.first)
        assertEquals("#8 phase=connected", ev?.second?.first())
    }
}

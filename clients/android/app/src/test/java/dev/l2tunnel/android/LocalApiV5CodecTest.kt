package dev.l2tunnel.android

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException

class LocalApiV5CodecTest {
    @Test
    fun roundTripsLengthDelimitedRequestAndStatusReply() {
        val reqBytes = LocalApiV5Codec.encodeRequest(JSONObject().put("command", "status"))
        val wire = ByteArrayOutputStream()
        LocalApiV5Codec.writeFrame(wire, reqBytes)
        val decodedReq = LocalApiV5Codec.readFrame(ByteArrayInputStream(wire.toByteArray()))
        assertEquals(5, decodedReq.getInt("version"))
        assertEquals("status", decodedReq.getJSONObject("action").getString("command"))

        val replyJson = JSONObject(
            """
            {
              "version": 5,
              "ok": true,
              "status": {
                "phase": "connected",
                "next_request_key": 4,
                "connected_ms": 12450,
                "observation": {
                  "peer": "198.51.100.10:24461",
                  "carrier": "udp",
                  "udp_cover": "quic-like"
                },
                "recovery": {
                  "active": false,
                  "attempt": 0,
                  "max_attempts": 8,
                  "total_recoveries": 1
                }
              }
            }
            """.trimIndent(),
        )
        val status = LocalApiV5Codec.parseStatus(replyJson)
        assertTrue(status.ok)
        assertEquals("connected", status.phase)
        assertEquals(4L, status.nextRequestKey)
        assertEquals("198.51.100.10:24461", status.peer)
        assertEquals("quic-like", status.cover)
        assertEquals(12450L, status.connectedMs)
        assertNotNull(status.recovery)
        assertFalse(status.recovery!!.active)
        assertEquals(1L, status.recovery!!.totalRecoveries)
    }

    @Test(expected = IOException::class)
    fun rejectsOversizedReplyFrame() {
        val bad = byteArrayOf(0x01, 0x00, 0x00, 0x00) // 16 MiB > RESPONSE_LIMIT
        LocalApiV5Codec.readFrame(ByteArrayInputStream(bad))
    }

    @Test
    fun parsesCarrierSwitchAndMetricsReplies() {
        val carrier = LocalApiV5Codec.parseCarrier(
            JSONObject(
                """
                {
                  "ok": true,
                  "carrier_switch": {
                    "supported": true,
                    "current_cover": "media-like",
                    "local": "0.0.0.0:45100",
                    "peer": "198.51.100.10:24462",
                    "switches": 2
                  }
                }
                """.trimIndent(),
            ),
        )
        assertNotNull(carrier)
        assertTrue(carrier!!.supported)
        assertEquals("media-like", carrier.currentCover)
        assertEquals(2L, carrier.switches)

        val metrics = LocalApiV5Codec.parseMetrics(
            JSONObject(
                """
                {
                  "ok": true,
                  "metrics": {
                    "wire": {
                      "sent_bytes": 1048576,
                      "received_packets": 1800
                    },
                    "device": {
                      "read_packets": 900,
                      "written_packets": 1750
                    },
                    "rtt_micros": 31200
                  }
                }
                """.trimIndent(),
            ),
        )
        assertNotNull(metrics)
        assertEquals(1048576L, metrics!!.wireSentBytes)
        assertEquals(1800L, metrics.wireReceivedPackets)
        assertEquals(31200L, metrics.rttMicros)
    }
}

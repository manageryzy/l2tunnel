//! Portable observations of genuine original raw carriers; never transfer authority.
use serde::{Deserialize, Serialize};

/// Complete requested or genuinely accepted packet policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPacketPolicy {
    /// Complete IPv4 packet ceiling.
    pub mtu: u16,
    /// Actual outer integrity/confidentiality suite.
    pub protection: String,
    /// Per-lane bounded packet slots.
    pub queue_packets: u16,
    /// Byte reordering/window horizon.
    pub horizon_bytes: u32,
    /// Minimum remaining useful post-transition byte budget.
    pub minimum_transfer_bytes: u32,
    /// Shared IP-byte pacing rate across both lanes and all record kinds.
    pub bytes_per_second: u64,
    /// Shared physical packet pacing rate.
    pub packets_per_second: u32,
    /// Shared finite byte burst.
    pub burst_bytes: u32,
    /// Shared finite packet burst.
    pub burst_packets: u16,
    /// Actual per-direction key packet ceiling.
    pub max_key_packets: u64,
    /// Actual per-direction authenticated plaintext byte ceiling.
    pub max_key_bytes: u64,
}

/// One occupied original lane, in global client/server order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLane {
    /// Original global client endpoint.
    pub client: String,
    /// Original global server endpoint.
    pub server: String,
    /// Genuine nonsecret outer session identity.
    pub session: [u8; 16],
    /// Actual TLS/member configuration commitment.
    pub configuration: [u8; 32],
}

/// Requested configuration and facts from the actual TLS/member handoff.
/// No field claims native kernel, firewall or platform qualification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawCarrier {
    /// Explicit requested carrier name.
    pub requested: String,
    /// Carrier that actually completed its handshake.
    pub effective: String,
    /// Project record appearance inside the selected raw carrier.
    pub inner_cover: String,
    /// Actual single Full connection or paired Half connections.
    pub duplex: String,
    /// Original pre-TLS Common configuration commitment.
    pub requested_configuration: [u8; 32],
    /// Original offline envelope E0.
    pub requested_envelope: [u8; 32],
    /// Original complete requested catalog commitment.
    pub requested_catalog: [u8; 32],
    /// Actual Common configuration bound to this outer session.
    pub effective_configuration: [u8; 32],
    /// Actual authenticated envelope E1.
    pub effective_envelope: [u8; 32],
    /// Actual complete catalog commitment.
    pub effective_catalog: [u8; 32],
    /// Complete requested packet policy, without hidden adjustment.
    pub requested_policy: RawPacketPolicy,
    /// Complete policy accepted by the actual original owners.
    pub effective_policy: RawPacketPolicy,
    /// Genuine original-carrier commitment used by the inner handshake.
    pub binding: [u8; 32],
    /// Actual accepted outer packet policy commitment.
    pub policy_digest: [u8; 32],
    /// Actual original pairing profile commitment.
    pub profile_digest: [u8; 32],
    /// Exact per-packet IPv4 and TCP header cost.
    pub ip_tcp_bytes: u64,
    /// Exact outer protected record and phase framing cost.
    pub record_overhead_bytes: u64,
    /// Exact upper protected record capacity within the original MTU.
    pub max_record_bytes: u64,
    /// Actual occupied originals; an unused second lane remains absent.
    pub lanes: [Option<RawLane>; 2],
}

#[cfg(unix)]
impl From<l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy> for RawPacketPolicy {
    fn from(value: l2tunnel_raw_io::handoff::pairing::packet::PacketPolicy) -> Self {
        use l2tunnel_raw_io::handoff::pairing::packet::Protection;
        Self {
            mtu: value.mtu,
            protection: match value.protection {
                Protection::ChaCha20Poly1305 => "chacha20-poly1305",
                Protection::HmacSha256 => "hmac-sha256",
            }
            .into(),
            queue_packets: value.queue_packets,
            horizon_bytes: value.horizon_bytes,
            minimum_transfer_bytes: value.minimum_transfer_bytes,
            bytes_per_second: value.bytes_per_second,
            packets_per_second: value.packets_per_second,
            burst_bytes: value.burst_bytes,
            burst_packets: value.burst_packets,
            max_key_packets: value.max_key_packets,
            max_key_bytes: value.max_key_bytes,
        }
    }
}

#[cfg(unix)]
impl RawCarrier {
    pub(super) fn observe(
        profile: &crate::secure_udp::common_transaction_profile::Profile,
        configuration: l2tunnel_security::ConfigDigest,
        inner_cover: &str,
    ) -> std::io::Result<Option<Self>> {
        use super::invalid;
        let Some(outer) = profile.raw_binding() else {
            return Ok(None);
        };
        let requested = profile
            .raw_policy()
            .ok_or_else(|| invalid("raw proof has no requested policy"))?;
        if requested != outer.policy() {
            return Err(invalid(
                "actual raw packet policy differs from requested policy",
            ));
        }
        let infos = outer.lane_infos();
        let tuples = outer.lane_endpoints();
        let mut lanes = [None, None];
        for index in 0..2 {
            lanes[index] = match (infos[index], tuples[index]) {
                (Some(info), Some((client, server))) => Some(RawLane {
                    client: client.to_string(),
                    server: server.to_string(),
                    session: info.session_id,
                    configuration: info.config.digest.0,
                }),
                (None, None) => None,
                _ => return Err(invalid("actual raw lane identity and tuple disagree")),
            };
        }
        let number = |n| u64::try_from(n).map_err(invalid);
        let geometry = outer.geometry();
        Ok(Some(Self {
            requested: "raw-packet".into(),
            effective: "raw-packet".into(),
            inner_cover: inner_cover.into(),
            duplex: match outer.duplex() {
                l2tunnel_core::Duplex::Full => "full",
                l2tunnel_core::Duplex::Half => "half",
            }
            .into(),
            requested_configuration: profile.requested_configuration()?.0,
            requested_envelope: *profile.requested_envelope().as_bytes(),
            requested_catalog: *profile.requested_catalog().root().as_bytes(),
            effective_configuration: configuration.0,
            effective_envelope: *profile.envelope().as_bytes(),
            effective_catalog: *profile.catalog().root().as_bytes(),
            requested_policy: requested.into(),
            effective_policy: outer.policy().into(),
            binding: outer.binding(),
            policy_digest: outer.policy_digest(),
            profile_digest: outer.profile().0,
            ip_tcp_bytes: number(geometry.ip_tcp_bytes)?,
            record_overhead_bytes: number(geometry.record_overhead_bytes)?,
            max_record_bytes: number(geometry.max_record_bytes)?,
            lanes,
        }))
    }
}

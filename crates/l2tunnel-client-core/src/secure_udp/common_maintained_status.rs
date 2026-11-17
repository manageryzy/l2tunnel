//! Portable requested/effective maintained transport observations.
use serde::{Deserialize, Serialize};
/// Exact requested record bounds; charges are allowances, not physical byte facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainedPolicy {
    /// Explicit actual transport family.
    pub carrier: String,
    /// Explicit Full/Half original topology.
    pub duplex: String,
    /// Canonical complete outer policy commitment.
    pub policy: [u8; 32],
    /// Logical path admission ceiling.
    pub path_mtu: u64,
    /// Complete final inner record capacity.
    pub max_record_bytes: u64,
    /// Covered original bootstrap capacity.
    pub max_bootstrap_bytes: u64,
    /// Per-final-record conservative transport allowance.
    pub charged_overhead_bytes: u64,
    /// Per-bootstrap-record conservative transport allowance.
    pub bootstrap_overhead_bytes: u64,
    /// Exact application framing overhead, independently of mandatory outer AEAD.
    pub framing_bytes: u64,
}
/// Actual original connection observations; copied fields confer no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainedLane {
    /// Observed original local address.
    pub local: String,
    /// Observed original remote address.
    pub peer: String,
    /// Genuine TLS/member session identity.
    pub session: [u8; 16],
    /// Complete authenticated outer configuration.
    pub configuration: [u8; 32],
}
/// Maintained transport status, separate from inner compact protection and QoS claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintainedCarrier {
    /// Explicit immutable request, before actual authentication.
    pub requested: MaintainedPolicy,
    /// Present only when the actual running Driver reports its installed owner.
    pub effective: Option<MaintainedPolicy>,
    /// Actual fresh outer binding, only when the Driver reports it.
    pub binding: Option<[u8; 32]>,
    /// Actual original authenticated connections, never requested tuple substitution.
    pub lanes: [Option<MaintainedLane>; 2],
    /// Named observed local acceptance boundary; not an IP transmission receipt.
    pub send_boundary: Option<String>,
    /// Mandatory maintained TLS/QUIC AEAD remains in addition to inner protection.
    pub outer_protection: String,
    /// Physical wire size includes transport packetization/retransmissions and is unmeasured.
    pub physical_wire_bytes_observed: bool,
    /// Configured independent public SNI is unavailable for genuine Quinn.
    pub independent_sni_supported: bool,
}
#[cfg(unix)]
impl MaintainedPolicy {
    fn from_request(
        request: l2tunnel_runtime::secure_udp::maintained::Request,
    ) -> std::io::Result<Self> {
        let g = request.geometry;
        let n = |value| u64::try_from(value).map_err(std::io::Error::other);
        Ok(Self {
            carrier: match request.kind {
                l2tunnel_runtime::secure_udp::maintained::Kind::TlsStream => "tcp",
                l2tunnel_runtime::secure_udp::maintained::Kind::QuicDatagram => "quic",
            }
            .into(),
            duplex: match request.duplex {
                l2tunnel_core::Duplex::Full => "full",
                l2tunnel_core::Duplex::Half => "half",
            }
            .into(),
            policy: request.policy.0,
            path_mtu: n(g.path_mtu)?,
            max_record_bytes: n(g.max_record_bytes)?,
            max_bootstrap_bytes: n(g.max_bootstrap_bytes)?,
            charged_overhead_bytes: n(g.charged_overhead_bytes)?,
            bootstrap_overhead_bytes: n(g.bootstrap_overhead_bytes)?,
            framing_bytes: n(g.framing_bytes)?,
        })
    }
}
#[cfg(unix)]
impl MaintainedCarrier {
    pub(crate) fn observe(
        profile: &crate::secure_udp::common_transaction_profile::Profile,
        snapshot: Option<&l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    ) -> std::io::Result<Option<Self>> {
        let Some(settings) = profile.maintained_settings() else {
            if snapshot.is_some_and(|value| value.maintained.is_some()) {
                return Err(std::io::Error::other("unexpected maintained runtime owner"));
            }
            return Ok(None);
        };
        let request = settings.request(profile.connection())?;
        let actual = snapshot.and_then(|value| value.maintained);
        if let Some(actual) = actual
            && (profile.maintained_binding() != Some(actual)
                || actual.requested() != request
                || snapshot.is_none_or(|value| value.send_boundary != request.kind.send_boundary()))
        {
            return Err(std::io::Error::other(
                "maintained runtime differs from authenticated plan",
            ));
        }
        let lanes = actual.map_or([None, None], |outer| {
            outer.lanes().map(|lane| {
                lane.map(|lane| MaintainedLane {
                    local: lane.local.to_string(),
                    peer: lane.peer.to_string(),
                    session: lane.info.session_id,
                    configuration: lane.info.config.digest.0,
                })
            })
        });
        Ok(Some(Self {
            requested: MaintainedPolicy::from_request(request)?,
            effective: actual
                .map(|outer| MaintainedPolicy::from_request(outer.requested()))
                .transpose()?,
            binding: actual.map(|outer| outer.binding()),
            lanes,
            send_boundary: actual.map(|_| format!("{:?}", request.kind.send_boundary())),
            outer_protection: "mandatory-maintained-aead-additional-to-inner".into(),
            physical_wire_bytes_observed: false,
            independent_sni_supported: matches!(
                request.kind,
                l2tunnel_runtime::secure_udp::maintained::Kind::TlsStream
            ),
        }))
    }
}

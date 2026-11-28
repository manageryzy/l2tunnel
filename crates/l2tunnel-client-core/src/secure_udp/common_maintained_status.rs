//! Portable requested/effective maintained transport observations.
use serde::{Deserialize, Serialize};
/// Per-original-lane queue bounds, never dynamic occupancy or physical flight.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicQueues {
    /// Configured maintained receive queue and adapter custody ceiling.
    pub maintained_queue_bytes: u64,
    /// Effective outgoing Quinn FIFO ceiling installed for Common records.
    pub maintained_send_queue_bytes: u64,
}
impl QuicQueues {
    fn new(receive: usize, send: usize) -> std::io::Result<Self> {
        Ok(Self {
            maintained_queue_bytes: u64::try_from(receive).map_err(std::io::Error::other)?,
            maintained_send_queue_bytes: u64::try_from(send).map_err(std::io::Error::other)?,
        })
    }
}

/// Availability of the local TCP unsent-data scheduling option.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsQueueAvailability {
    /// No actual running maintained owner has reported its sockets yet.
    NotObserved,
    /// Actual lanes have no platform readback; no bounded-queue claim is made.
    Unavailable,
    /// Every actual lane reports the requested threshold installed.
    Installed,
}

/// Local TCP scheduling observations, outside the authenticated wire policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSendQueue {
    /// Derived local request, not a negotiated transport or memory bound.
    pub requested_notsent_lowat_bytes: u64,
    /// Actual First/Second socket readbacks. None is unavailable or absent;
    /// the actual lane inventory distinguishes those cases.
    pub effective_notsent_lowat_bytes: [Option<u64>; 2],
    /// Installation is reported only from actual retained socket observations.
    pub availability: TlsQueueAvailability,
}
impl TlsSendQueue {
    fn observe(
        request: l2tunnel_runtime::secure_udp::maintained::Request,
        actual: Option<l2tunnel_runtime::secure_udp::maintained::Authenticated>,
    ) -> std::io::Result<Option<Self>> {
        if request.kind != l2tunnel_runtime::secure_udp::maintained::Kind::TlsStream {
            return Ok(None);
        }
        let requested = u64::from(l2tunnel_runtime::retained_tls::tcp_notsent_lowat_bytes(
            request.geometry.max_record_bytes,
        )?);
        let effective = actual.map(|owner| {
            owner.lanes().map(|lane| {
                lane.and_then(|lane| lane.tcp_notsent_lowat_bytes)
                    .map(u64::from)
            })
        });
        Self::from_readbacks(requested, request.duplex, effective).map(Some)
    }

    fn from_readbacks(
        requested: u64,
        duplex: l2tunnel_core::Duplex,
        effective: Option<[Option<u64>; 2]>,
    ) -> std::io::Result<Self> {
        let count = if duplex == l2tunnel_core::Duplex::Full {
            1
        } else {
            2
        };
        let availability = match effective {
            None => TlsQueueAvailability::NotObserved,
            Some(values) => {
                if values.iter().flatten().any(|value| *value != requested)
                    || (count == 1 && values[1].is_some())
                {
                    return Err(std::io::Error::other(
                        "actual TCP unsent threshold differs from local request",
                    ));
                }
                if values[..count].iter().all(Option::is_some) {
                    TlsQueueAvailability::Installed
                } else {
                    TlsQueueAvailability::Unavailable
                }
            }
        };
        Ok(Self {
            requested_notsent_lowat_bytes: requested,
            effective_notsent_lowat_bytes: effective.unwrap_or([None, None]),
            availability,
        })
    }
}
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
    /// Global First/Second lane queue geometry; None means unavailable or non-QUIC.
    #[serde(default)]
    pub quic_queues: Option<[Option<QuicQueues>; 2]>,
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
    /// Local TCP scheduling only. The threshold can be exceeded by kernel
    /// buffering; it is not occupancy, physical flight or a hard FIFO capacity.
    #[serde(default)]
    pub local_tls_send_queue: Option<TlsSendQueue>,
}
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
            quic_queues: None,
        })
    }
}
impl MaintainedCarrier {
    /// Compare all requested policy fields, preserving observed-only queue facts.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn matches_requested_policy(&self) -> bool {
        let Some(effective) = self.effective.as_ref() else {
            return false;
        };
        let mut requested = self.requested.clone();
        // Proxy requests retain generic authenticated geometry without the
        // original Quinn profiles. Absence is unknown, not a zero queue bound.
        if requested.quic_queues.is_none() {
            requested.quic_queues = effective.quic_queues;
        }
        *effective == requested
    }

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
        let mut observed = Self::from_observation(request, actual)?;
        if let crate::secure_udp::maintained::Transport::Quic(profiles) = settings.transport {
            let [first, second] = profiles.map(|profile| {
                profile
                    .map(|profile| {
                        QuicQueues::new(
                            profile
                                .datagram_queue_bytes()
                                .map_err(std::io::Error::other)?,
                            profile
                                .datagram_send_queue_bytes()
                                .map_err(std::io::Error::other)?,
                        )
                    })
                    .transpose()
            });
            let queues = Some([first?, second?]);
            if observed
                .effective
                .as_ref()
                .is_some_and(|effective| effective.quic_queues != queues)
            {
                return Err(std::io::Error::other(
                    "actual QUIC queues differ from requested profiles",
                ));
            }
            observed.requested.quic_queues = queues;
        }
        Ok(Some(observed))
    }
    pub(crate) fn from_observation(
        request: l2tunnel_runtime::secure_udp::maintained::Request,
        actual: Option<l2tunnel_runtime::secure_udp::maintained::Authenticated>,
    ) -> std::io::Result<Self> {
        if actual.is_some_and(|value| value.requested() != request) {
            return Err(std::io::Error::other(
                "maintained runtime policy differs from request",
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
        let effective = actual
            .map(|outer| {
                let mut effective = MaintainedPolicy::from_request(outer.requested())?;
                if request.kind == l2tunnel_runtime::secure_udp::maintained::Kind::QuicDatagram {
                    let [first, second] = outer.lanes().map(|lane| {
                        lane.and_then(|lane| lane.quic_queues)
                            .map(|queues| {
                                QuicQueues::new(
                                    queues.maintained_queue_bytes,
                                    queues.maintained_send_queue_bytes,
                                )
                            })
                            .transpose()
                    });
                    effective.quic_queues = Some([first?, second?]);
                }
                Ok::<_, std::io::Error>(effective)
            })
            .transpose()?;
        Ok(Self {
            requested: MaintainedPolicy::from_request(request)?,
            effective,
            binding: actual.map(|outer| outer.binding()),
            lanes,
            send_boundary: actual.map(|_| format!("{:?}", request.kind.send_boundary())),
            outer_protection: "mandatory-maintained-aead-additional-to-inner".into(),
            physical_wire_bytes_observed: false,
            independent_sni_supported: matches!(
                request.kind,
                l2tunnel_runtime::secure_udp::maintained::Kind::TlsStream
            ),
            local_tls_send_queue: TlsSendQueue::observe(request, actual)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_core::Duplex;

    #[test]
    fn tls_queue_status_separates_request_unavailable_and_actual_readback() -> std::io::Result<()> {
        let requested = TlsSendQueue::from_readbacks(2870, Duplex::Full, None)?;
        assert_eq!(requested.availability, TlsQueueAvailability::NotObserved);
        assert_eq!(requested.effective_notsent_lowat_bytes, [None, None]);
        let unavailable = TlsSendQueue::from_readbacks(2870, Duplex::Full, Some([None, None]))?;
        assert_eq!(unavailable.availability, TlsQueueAvailability::Unavailable);
        assert_eq!(unavailable.effective_notsent_lowat_bytes, [None, None]);
        for (duplex, values) in [
            (Duplex::Full, [Some(2870), None]),
            (Duplex::Half, [Some(2870), Some(2870)]),
        ] {
            let observed = TlsSendQueue::from_readbacks(2870, duplex, Some(values))?;
            assert_eq!(observed.availability, TlsQueueAvailability::Installed);
            assert_eq!(observed.effective_notsent_lowat_bytes, values);
        }
        assert!(
            TlsSendQueue::from_readbacks(2870, Duplex::Full, Some([Some(2871), None])).is_err()
        );
        assert!(TlsSendQueue::from_readbacks(2870, Duplex::Full, Some([Some(2870); 2])).is_err());
        let incomplete =
            TlsSendQueue::from_readbacks(2870, Duplex::Half, Some([Some(2870), None]))?;
        assert_eq!(incomplete.availability, TlsQueueAvailability::Unavailable);
        Ok(())
    }
}

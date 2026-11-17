//! Explicit maintained-transport policy and actual authenticated owner evidence.
//! Admission charges are configured allowances, never measured physical bytes.
use l2tunnel_auth::{SessionConfig, SessionInfo};
use l2tunnel_core::{ConfigDigest, Duplex};
use ring::digest;
use std::{io, net::SocketAddr};
use tokio::time::Instant;

/// Maintained compatibility transports; neither names the header-only UDP cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Genuine TLS records over the original TCP stream(s).
    TlsStream,
    /// Genuine Quinn DATAGRAMs over the original UDP connection(s).
    QuicDatagram,
}
impl Kind {
    /// Actual local handoff, not a physical transmission timestamp.
    pub const fn send_boundary(self) -> super::SendBoundary {
        match self {
            Self::TlsStream => super::SendBoundary::TlsStreamFlushed,
            Self::QuicDatagram => super::SendBoundary::QuicDatagramAccepted,
        }
    }
}
/// Explicit application-record bounds and conservative transport admission costs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Geometry {
    /// Requested path budget used to size a single logical record.
    pub path_mtu: usize,
    /// Largest selected final Records body accepted by the actual adapter.
    pub max_record_bytes: usize,
    /// Largest initial Noise/member message, before the bootstrap envelope.
    pub max_bootstrap_bytes: usize,
    /// Selected final per-record admission allowance, including transport framing.
    pub charged_overhead_bytes: usize,
    /// Initial per-record allowance, including retained bootstrap framing.
    pub bootstrap_overhead_bytes: usize,
    /// Exact application framing bytes; underlying TLS/QUIC costs remain separate.
    pub framing_bytes: usize,
}
impl Geometry {
    /// Refuse incompatible bounds instead of truncating a selected algorithm.
    pub fn validate(self) -> io::Result<()> {
        if !(256..=65_535).contains(&self.path_mtu)
            || self.max_record_bytes == 0
            || self.max_bootstrap_bytes == 0
            || self.framing_bytes > self.charged_overhead_bytes
            || self.bootstrap_overhead_bytes < self.charged_overhead_bytes
        {
            return Err(invalid("maintained carrier geometry"));
        }
        self.charge(self.max_record_bytes, false)?;
        self.charge(self.max_bootstrap_bytes, true)?;
        Ok(())
    }
    /// Configured admission cost; TCP retransmissions and Quinn ACKs are not counted.
    pub fn charge(self, bytes: usize, bootstrap: bool) -> io::Result<usize> {
        let (maximum, overhead) = if bootstrap {
            (self.max_bootstrap_bytes, self.bootstrap_overhead_bytes)
        } else {
            (self.max_record_bytes, self.charged_overhead_bytes)
        };
        bytes
            .checked_add(overhead)
            .filter(|cost| bytes != 0 && bytes <= maximum && *cost <= self.path_mtu)
            .ok_or_else(|| invalid("maintained carrier record exceeds selected geometry"))
    }
}
/// Complete selected policy supplied before genuine transport authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    /// Maintained TLS or genuine QUIC, independently of the record algorithm.
    pub kind: Kind,
    /// Full or genuinely paired half-duplex original connections.
    pub duplex: Duplex,
    /// Exact selected bounds and admission basis.
    pub geometry: Geometry,
    /// Canonical complete outer policy, including every lane and queue/timer bound.
    pub policy: ConfigDigest,
}
impl Request {
    /// Validate local policy before opening a socket or constructing retained owners.
    pub fn validate(self) -> io::Result<()> {
        self.geometry.validate()?;
        if self.policy.0 == [0; 32] {
            return Err(invalid(
                "maintained carrier requires a complete policy digest",
            ));
        }
        Ok(())
    }
    /// Domain-separated policy commitment; observed effective state is not invented.
    pub fn digest(self) -> io::Result<ConfigDigest> {
        self.validate()?;
        let mut h = digest::Context::new(&digest::SHA256);
        h.update(b"l2tunnel/common-maintained/request/v1\0");
        h.update(&[
            match self.kind {
                Kind::TlsStream => 1,
                Kind::QuicDatagram => 2,
            },
            match self.duplex {
                Duplex::Full => 1,
                Duplex::Half => 2,
            },
        ]);
        for value in [
            self.geometry.path_mtu,
            self.geometry.max_record_bytes,
            self.geometry.max_bootstrap_bytes,
            self.geometry.charged_overhead_bytes,
            self.geometry.bootstrap_overhead_bytes,
            self.geometry.framing_bytes,
        ] {
            h.update(
                &u64::try_from(value)
                    .map_err(io::Error::other)?
                    .to_be_bytes(),
            );
        }
        h.update(&self.policy.0);
        Ok(ConfigDigest(finish(h)))
    }
}
/// Queue bounds copied from a genuine QUIC owner, without occupancy or flight claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicQueues {
    /// Configured receive queue and adapter custody ceiling, not occupancy.
    pub maintained_queue_bytes: usize,
    /// Actual outgoing Quinn FIFO ceiling, not physical in-flight bytes.
    pub maintained_send_queue_bytes: usize,
}
/// Actual verified lane; copied observations cannot construct its transport owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lane {
    /// Real TLS/member result from this original lane.
    pub info: SessionInfo,
    /// Actual local original endpoint.
    pub local: SocketAddr,
    /// Actual peer endpoint, never a replacement for cryptographic identity.
    pub peer: SocketAddr,
    /// Queue bounds obtained from the genuine QUIC owner; absent for TLS.
    pub quic_queues: Option<QuicQueues>,
}
/// Opaque genuine Full/Half proof used by the subsequent Noise/member handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Authenticated {
    pub(crate) requested: Request,
    pub(crate) common_configuration: SessionConfig,
    pub(crate) lanes: [Option<Lane>; 2],
    pub(crate) binding: [u8; 32],
    pub(crate) deadline: Instant,
}
impl Authenticated {
    /// Complete Common request authenticated by every original outer lane.
    pub const fn common_configuration(self) -> SessionConfig {
        self.common_configuration
    }
    /// Requested policy authenticated before exposing this owner.
    pub const fn requested(self) -> Request {
        self.requested
    }
    /// Verified original lanes in global first/second order.
    pub const fn lanes(self) -> [Option<Lane>; 2] {
        self.lanes
    }
    /// Fresh actual outer binding committed by the common inner session.
    pub const fn binding(self) -> [u8; 32] {
        self.binding
    }
    /// Original setup cap; no factory or layer renews it.
    pub const fn deadline(self) -> Instant {
        self.deadline
    }
    /// Actual first-lane member/server identity, not a caller-provided label.
    pub fn info(self) -> io::Result<SessionInfo> {
        self.lanes[0]
            .map(|lane| lane.info)
            .ok_or_else(|| invalid("missing authenticated first lane"))
    }
    /// Original first-lane endpoints in global client/server order.
    pub fn endpoints(self) -> io::Result<(SocketAddr, SocketAddr)> {
        let lane = self.lanes[0].ok_or_else(|| invalid("missing authenticated first lane"))?;
        Ok(if lane.info.peer_member.is_none() {
            (lane.local, lane.peer)
        } else {
            (lane.peer, lane.local)
        })
    }
    pub(crate) fn checked(
        requested: Request,
        common_configuration: SessionConfig,
        lanes: [Option<Lane>; 2],
        expected: [Option<SessionConfig>; 2],
        deadline: Instant,
    ) -> io::Result<Self> {
        requested.validate()?;
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let first = lanes[0].ok_or_else(|| invalid("missing actual maintained first lane"))?;
        let count = if requested.duplex == Duplex::Half {
            2
        } else {
            1
        };
        if lanes.iter().flatten().count() != count || expected.iter().flatten().count() != count {
            return Err(invalid(
                "maintained duplex differs from original lane count",
            ));
        }
        let mut h = digest::Context::new(&digest::SHA256);
        h.update(b"l2tunnel/common-maintained/actual-outer/v1\0");
        h.update(&requested.digest()?.0);
        h.update(&common_configuration.digest.0);
        for (lane, expected) in lanes.into_iter().zip(expected) {
            let (lane, expected) = match (lane, expected) {
                (Some(lane), Some(expected)) => (lane, expected),
                (None, None) => continue,
                _ => {
                    return Err(invalid(
                        "maintained actual and expected lane positions differ",
                    ));
                }
            };
            match (requested.kind, lane.quic_queues) {
                (Kind::TlsStream, None) => {}
                (Kind::QuicDatagram, Some(queues))
                    if queues.maintained_send_queue_bytes > 0
                        && queues.maintained_send_queue_bytes <= queues.maintained_queue_bytes => {}
                _ => return Err(invalid("maintained actual queue observations differ")),
            }
            // Scoped routing attributes are host-local, not a shared peer tuple.
            // This selected binding requires unscoped addresses until local route
            // selection and canonical peer identity have separate representations.
            if [lane.local, lane.peer].into_iter().any(|address| {
                matches!(address, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
            }) {
                return Err(invalid("maintained binding requires unscoped IPv6 endpoints"));
            }
            if lane.info.config != expected
                || lane.info.member != first.info.member
                || lane.info.server != first.info.server
                || lane.info.peer_member.is_some() != first.info.peer_member.is_some()
                || lane.local.is_ipv4() != first.local.is_ipv4()
                || lane.local.is_ipv4() != lane.peer.is_ipv4()
                || lane.local.ip().is_unspecified()
                || lane.peer.ip().is_unspecified()
                || lane
                    .info
                    .peer_member
                    .is_some_and(|key| key != lane.info.member)
            {
                return Err(invalid("maintained actual lane authentication differs"));
            }
            h.update(&lane.info.session_id);
            h.update(&lane.info.config.digest.0);
            h.update(&[match lane.info.config.layer {
                l2tunnel_device::PacketLayer::Ethernet => 1,
                l2tunnel_device::PacketLayer::Ip => 2,
            }]);
            h.update(&lane.info.member.0);
            h.update(&lane.info.server.0);
            let endpoints = if first.info.peer_member.is_none() {
                [lane.local, lane.peer]
            } else {
                [lane.peer, lane.local]
            };
            for endpoint in endpoints {
                bind_endpoint(&mut h, endpoint);
            }
        }
        if let Some(second) = lanes[1]
            && (second.info.session_id == first.info.session_id
                || (second.local, second.peer) == (first.local, first.peer))
        {
            return Err(invalid("maintained half requires distinct original lanes"));
        }
        Ok(Self {
            requested,
            common_configuration,
            lanes,
            binding: finish(h),
            deadline,
        })
    }
}
fn finish(hash: digest::Context) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(hash.finish().as_ref());
    out
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn bind_endpoint(hash: &mut digest::Context, endpoint: SocketAddr) {
    match endpoint {
        SocketAddr::V4(address) => {
            hash.update(&[4]);
            hash.update(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            hash.update(&[6]);
            hash.update(&address.ip().octets());
            hash.update(&address.flowinfo().to_be_bytes());
            hash.update(&address.scope_id().to_be_bytes());
        }
    }
    hash.update(&endpoint.port().to_be_bytes());
}

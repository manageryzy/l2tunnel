//! Authenticated in-band live carrier / UDP cover switching (`ProfileTag::CarrierSwitchV1`,
//! `DGUI-14`).
//!
//! Performs make-before-break migration on an active Common UDP session without
//! dropping the session, resetting the record engine/epoch, or interrupting
//! inner TUN/TAP flows:
//! 1. Initiator sends authenticated `Propose(id, target)` on the `Liveness`
//!    control stream (`Control` scope).
//! 2. Responder binds a fresh standby UDP socket on its local IP and replies
//!    with authenticated `Ready(id, target, standby_port, 256-bit token)`.
//! 3. Initiator binds a fresh standby UDP socket, connects to
//!    `(peer_ip, standby_port)`, and sends cover-framed (`l2tunnel-cover`)
//!    `L2CS` probes carrying `id` and `token` while active traffic continues on
//!    the existing socket.
//! 4. Responder verifies the cover-framed `L2CS` probe, connects its standby
//!    socket to the initiator's standby address, and replies with `L2CA`.
//! 5. Once Initiator verifies `L2CA`, it sends authenticated `Commit(id, target,
//!    token)` on the active `Control` stream. Responder swaps `IoOwner::Udp` to
//!    the verified standby socket and sends `L2CK` + authenticated `CommitAck`
//!    on the new socket; Initiator swaps `IoOwner::Udp` upon receiving `L2CK`
//!    or the first Common packet on its standby socket.
//! 6. Any failure or timeout (3 s original deadline) drops only the standby
//!    socket and leaves the active carrier untouched.

use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex};

use l2tunnel_cover::{
    Appearance, Config as CoverConfig, ConnectionId, ConnectionIds, Limits as CoverLimits,
    MediaConfig, MediaTimestamp, PacketMeta, PacketNumber as CoverPacketNumber,
    Phase as CoverPhase, Ssrc,
};
use l2tunnel_security::Role;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tokio::time::Instant;

use super::carrier::{IoOwner, UdpIo};

/// Exact wire length of one `CarrierSwitchV1` control frame.
pub const FRAME_BYTES: usize = l2tunnel_management::session_control::CARRIER_SWITCH_BYTES;

const VERSION: u8 = 1;
const KIND_PROPOSE: u8 = 1;
const KIND_READY: u8 = 2;
const KIND_COMMIT: u8 = 3;
const KIND_COMMIT_ACK: u8 = 4;
const KIND_REFUSE: u8 = 5;

const CODE_OK: u8 = 0;
const CODE_UNSUPPORTED: u8 = 1;
const CODE_BUSY: u8 = 2;
const CODE_BIND_FAILED: u8 = 3;
const CODE_INVALID: u8 = 4;

const DEADLINE_US: u64 = 3_000_000;
const PROBE_INTERVAL_US: u64 = 100_000;
const POLL_WAKE_US: u64 = 25_000;
const MAX_OUTGOING: usize = 8;

const PROBE_MAGIC_REQ: [u8; 4] = *b"L2CS";
const PROBE_MAGIC_ACK: [u8; 4] = *b"L2CA";
const PROBE_MAGIC_COMMIT: [u8; 4] = *b"L2CK";
const PROBE_BODY_BYTES: usize = 4 + 4 + 1 + 32;
const ROLE_CLIENT: u8 = 1;
const ROLE_SERVER: u8 = 2;

/// Selectable live in-session UDP carrier cover target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CarrierTarget {
    /// UDP with QUIC-like outer cover (`quic-like`).
    UdpQuicLike = 1,
    /// UDP with minimal RTP/media-like outer cover (`media-like`).
    UdpMediaLike = 2,
    /// UDP with TLS 1.3 record-like outer cover (`tls-like`).
    UdpTlsLike = 3,
}

impl CarrierTarget {
    /// Canonical CLI/API identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UdpQuicLike => "quic-like",
            Self::UdpMediaLike => "media-like",
            Self::UdpTlsLike => "tls-like",
        }
    }

    /// Parse a canonical carrier/cover identifier.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "quic-like" => Some(Self::UdpQuicLike),
            "media-like" => Some(Self::UdpMediaLike),
            "tls-like" => Some(Self::UdpTlsLike),
            _ => None,
        }
    }

    /// Matching `l2tunnel-cover` appearance.
    pub const fn appearance(self) -> Appearance {
        match self {
            Self::UdpQuicLike => Appearance::QuicLike,
            Self::UdpMediaLike => Appearance::MediaLike,
            Self::UdpTlsLike => Appearance::TlsLike,
        }
    }

    /// Convert from a `l2tunnel-cover` appearance.
    pub const fn from_appearance(appearance: Appearance) -> Self {
        match appearance {
            Appearance::QuicLike => Self::UdpQuicLike,
            Appearance::MediaLike => Self::UdpMediaLike,
            Appearance::TlsLike => Self::UdpTlsLike,
        }
    }

    fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::UdpQuicLike),
            2 => Some(Self::UdpMediaLike),
            3 => Some(Self::UdpTlsLike),
            _ => None,
        }
    }
}

/// Failure of one live carrier switch request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierSwitchError {
    /// Active session carrier does not support live in-session switching (e.g. non-UDP).
    UnsupportedCarrier,
    /// Only the client (initiator) may propose a live carrier switch.
    NotCoordinator,
    /// Another carrier switch is already in progress.
    Busy,
    /// Standby UDP bind or connect failed locally.
    BindFailed,
    /// Standby cover-framed reachability probe did not complete before the deadline.
    ProbeFailed,
    /// Peer did not answer within the 3-second switch deadline.
    Timeout,
    /// Peer explicitly refused the requested carrier switch.
    PeerRefused,
    /// Peer sent a malformed carrier-switch message.
    Malformed,
    /// The session ended before the switch completed.
    Closed,
}

/// Completed live carrier switch observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierSwitchOutcome {
    /// Active UDP cover after the switch.
    pub target: CarrierTarget,
    /// New local bound UDP endpoint.
    pub local_addr: SocketAddr,
    /// New connected peer UDP endpoint.
    pub peer_addr: SocketAddr,
    /// Cumulative successful live carrier switches in this session.
    pub switches: u64,
}

/// Live carrier-switch state published in [`super::CommonSnapshot`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierSwitchSnapshot {
    /// Effective UDP cover after the latest live switch.
    pub effective_cover: Appearance,
    /// Active local UDP endpoint.
    pub local_addr: SocketAddr,
    /// Active peer UDP endpoint.
    pub peer_addr: SocketAddr,
    /// Total live carrier switches committed in this session.
    pub switches: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WireFrame {
    kind: u8,
    target: CarrierTarget,
    code: u8,
    id: u32,
    port: u16,
    token: [u8; 32],
}

impl WireFrame {
    fn encode(self) -> [u8; FRAME_BYTES] {
        let mut out = [0_u8; FRAME_BYTES];
        out[0] = VERSION;
        out[1] = self.kind;
        out[2] = self.target as u8;
        out[3] = self.code;
        out[4..8].copy_from_slice(&self.id.to_be_bytes());
        out[8..10].copy_from_slice(&self.port.to_be_bytes());
        out[12..44].copy_from_slice(&self.token);
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FRAME_BYTES || bytes[0] != VERSION {
            return None;
        }
        if bytes[10] != 0 || bytes[11] != 0 || bytes[44..56].iter().any(|&b| b != 0) {
            return None;
        }
        let kind = bytes[1];
        if !matches!(
            kind,
            KIND_PROPOSE | KIND_READY | KIND_COMMIT | KIND_COMMIT_ACK | KIND_REFUSE
        ) {
            return None;
        }
        let target = CarrierTarget::decode(bytes[2])?;
        let id = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if id == 0 {
            return None;
        }
        let port = u16::from_be_bytes([bytes[8], bytes[9]]);
        let mut token = [0_u8; 32];
        token.copy_from_slice(&bytes[12..44]);
        Some(Self {
            kind,
            target,
            code: bytes[3],
            id,
            port,
            token,
        })
    }
}

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn random_token() -> io::Result<[u8; 32]> {
    let mut token = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut token)
        .map_err(|_| io::Error::other("system randomness unavailable"))?;
    Ok(token)
}

fn probe_cover_config(
    target: CarrierTarget,
    token: &[u8; 32],
    is_initiator: bool,
) -> io::Result<CoverConfig> {
    let mut c_id = [0_u8; 8];
    let mut s_id = [0_u8; 8];
    c_id.copy_from_slice(&token[0..8]);
    s_id.copy_from_slice(&token[8..16]);
    let c_ssrc = u32::from_be_bytes([token[16], token[17], token[18], token[19]]);
    let s_ssrc = u32::from_be_bytes([token[20], token[21], token[22], token[23]]);
    let (local_id, peer_id, local_ssrc, peer_ssrc) = if is_initiator {
        (c_id, s_id, c_ssrc, s_ssrc)
    } else {
        (s_id, c_id, s_ssrc, c_ssrc)
    };
    CoverConfig::new(
        target.appearance(),
        ConnectionIds {
            local: ConnectionId(local_id),
            peer: ConnectionId(peer_id),
        },
        MediaConfig {
            local_ssrc: Ssrc(local_ssrc),
            peer_ssrc: Ssrc(peer_ssrc),
            payload_type: 96,
        },
        CoverLimits {
            max_packet_bytes: 256,
            max_protected_bytes: 128,
        },
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid standby cover config"))
}

fn encode_probe(
    target: CarrierTarget,
    token: &[u8; 32],
    is_initiator: bool,
    magic: [u8; 4],
    id: u32,
    seq: u32,
) -> io::Result<Vec<u8>> {
    let cfg = probe_cover_config(target, token, is_initiator)?;
    let mut body = [0_u8; PROBE_BODY_BYTES];
    body[0..4].copy_from_slice(&magic);
    body[4..8].copy_from_slice(&id.to_be_bytes());
    body[8] = if is_initiator {
        ROLE_CLIENT
    } else {
        ROLE_SERVER
    };
    body[9..41].copy_from_slice(token);
    let mut out = vec![0_u8; 128];
    let len = cfg
        .encode(
            PacketMeta {
                phase: CoverPhase::Handshake,
                packet_number: CoverPacketNumber(seq),
                media_timestamp: MediaTimestamp(seq.wrapping_mul(160)),
            },
            &body,
            &mut out,
        )
        .map_err(|_| io::Error::other("standby probe encode failed"))?;
    out.truncate(len);
    Ok(out)
}

fn decode_probe(
    target: CarrierTarget,
    token: &[u8; 32],
    is_initiator: bool,
    expected_magic: [u8; 4],
    expected_id: u32,
    packet: &[u8],
) -> bool {
    let Ok(cfg) = probe_cover_config(target, token, is_initiator) else {
        return false;
    };
    let Ok(decoded) = cfg.decode(packet) else {
        return false;
    };
    if decoded.protected.len() != PROBE_BODY_BYTES {
        return false;
    }
    if decoded.protected[0..4] != expected_magic {
        return false;
    }
    let id = u32::from_be_bytes([
        decoded.protected[4],
        decoded.protected[5],
        decoded.protected[6],
        decoded.protected[7],
    ]);
    let expected_role = if is_initiator {
        ROLE_SERVER
    } else {
        ROLE_CLIENT
    };
    if id != expected_id || decoded.protected[8] != expected_role {
        return false;
    }
    let mut got_token = [0_u8; 32];
    got_token.copy_from_slice(&decoded.protected[9..41]);
    constant_time_eq(&got_token, token)
}

type Outcome = Result<CarrierSwitchOutcome, CarrierSwitchError>;

struct Pending {
    id: u32,
    target: CarrierTarget,
    reply: oneshot::Sender<Outcome>,
}

struct SharedState {
    next_id: u32,
    queued: Option<Pending>,
    in_flight: Option<oneshot::Sender<Outcome>>,
    closed: bool,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            next_id: 1,
            queued: None,
            in_flight: None,
            closed: false,
        }
    }
}

/// Shared service-to-runtime handle for live carrier switching (at most one
/// switch in flight per session).
#[derive(Default)]
pub(super) struct Shared {
    state: Mutex<SharedState>,
}

impl Shared {
    pub(super) fn request(
        &self,
        target: CarrierTarget,
    ) -> Result<oneshot::Receiver<Outcome>, CarrierSwitchError> {
        let Ok(mut state) = self.state.lock() else {
            return Err(CarrierSwitchError::Closed);
        };
        if state.closed {
            return Err(CarrierSwitchError::Closed);
        }
        if state.queued.is_some() || state.in_flight.is_some() {
            return Err(CarrierSwitchError::Busy);
        }
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1).max(1);
        let (tx, rx) = oneshot::channel();
        state.queued = Some(Pending {
            id,
            target,
            reply: tx,
        });
        Ok(rx)
    }

    fn take_queued(&self) -> Option<(u32, CarrierTarget)> {
        let mut state = self.state.lock().ok()?;
        let pending = state.queued.take()?;
        state.in_flight = Some(pending.reply);
        Some((pending.id, pending.target))
    }

    fn finish(&self, result: Outcome) {
        if let Ok(mut state) = self.state.lock()
            && let Some(sender) = state.in_flight.take()
        {
            let _sent = sender.send(result);
        }
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            if let Some(queued) = state.queued.take() {
                let _sent = queued.reply.send(Err(CarrierSwitchError::Closed));
            }
            if let Some(sender) = state.in_flight.take() {
                let _sent = sender.send(Err(CarrierSwitchError::Closed));
            }
        }
    }
}

enum InitiatorPhase {
    /// Sent Propose; waiting for authenticated Ready.
    Proposed {
        frame: [u8; FRAME_BYTES],
        submitted: bool,
    },
    /// Bound standby UDP socket; probing until L2CA arrives.
    Probing {
        socket: UdpSocket,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        token: [u8; 32],
        last_probe_us: u64,
        seq: u32,
    },
    /// Probe verified! Sent Commit; waiting for L2CK or first Common packet on standby.
    Committing {
        socket: UdpSocket,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        token: [u8; 32],
        commit_frame: [u8; FRAME_BYTES],
        commit_submitted: bool,
    },
}

struct InitiatorActive {
    id: u32,
    target: CarrierTarget,
    deadline_us: u64,
    phase: InitiatorPhase,
}

struct ResponderStandby {
    id: u32,
    target: CarrierTarget,
    socket: UdpSocket,
    local_addr: SocketAddr,
    peer_addr: Option<SocketAddr>,
    token: [u8; 32],
    deadline_us: u64,
    commit_pending: bool,
    seq: u32,
}

/// Session-loop side of live carrier switching.
pub(super) struct Port {
    shared: Option<Arc<Shared>>,
    initiator: Option<InitiatorActive>,
    responder: Option<ResponderStandby>,
    outgoing: VecDeque<([u8; FRAME_BYTES], u64)>,
    effective_cover: Appearance,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    switches: u64,
    is_udp: bool,
}

impl Port {
    pub(super) fn new(
        shared: Option<Arc<Shared>>,
        initial_cover: Appearance,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        is_udp: bool,
    ) -> Self {
        Self {
            shared,
            initiator: None,
            responder: None,
            outgoing: VecDeque::with_capacity(MAX_OUTGOING),
            effective_cover: initial_cover,
            local_addr,
            peer_addr,
            switches: 0,
            is_udp,
        }
    }

    pub(super) fn snapshot(&self) -> CarrierSwitchSnapshot {
        CarrierSwitchSnapshot {
            effective_cover: self.effective_cover,
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
            switches: self.switches,
        }
    }

    fn complete_initiator(&mut self, result: Outcome) {
        self.initiator = None;
        if let Some(shared) = &self.shared {
            shared.finish(result);
        }
    }

    fn push_outgoing(&mut self, frame: [u8; FRAME_BYTES], deadline_us: u64) {
        if self.outgoing.len() < MAX_OUTGOING {
            self.outgoing.push_back((frame, deadline_us));
        }
    }

    fn wake_at(&self, now: u64) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        let mut consider = |at: u64| {
            earliest = Some(match earliest {
                Some(prev) => prev.min(at),
                None => at,
            });
        };
        if let Some(active) = &self.initiator {
            consider(active.deadline_us);
            if matches!(
                active.phase,
                InitiatorPhase::Probing { .. } | InitiatorPhase::Committing { .. }
            ) {
                consider(now.saturating_add(POLL_WAKE_US));
            }
        }
        if let Some(standby) = &self.responder {
            consider(standby.deadline_us);
            consider(now.saturating_add(POLL_WAKE_US));
        }
        if let Some((_, dl)) = self.outgoing.front() {
            consider(*dl);
        }
        earliest
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        if let Some(shared) = &self.shared {
            shared.close();
        }
    }
}

fn bind_standby_udp(local_ip: std::net::IpAddr) -> io::Result<(UdpSocket, SocketAddr)> {
    let std_sock = StdUdpSocket::bind(SocketAddr::new(local_ip, 0))?;
    std_sock.set_nonblocking(true)?;
    let addr = std_sock.local_addr()?;
    let sock = UdpSocket::from_std(std_sock)?;
    Ok((sock, addr))
}

fn bind_connected_standby_udp(
    local_ip: std::net::IpAddr,
    peer: SocketAddr,
) -> io::Result<(UdpSocket, SocketAddr)> {
    let std_sock = StdUdpSocket::bind(SocketAddr::new(local_ip, 0))?;
    std_sock.set_nonblocking(true)?;
    std_sock.connect(peer)?;
    let addr = std_sock.local_addr()?;
    let sock = UdpSocket::from_std(std_sock)?;
    Ok((sock, addr))
}

impl super::Driver {
    pub(super) fn install_carrier_switch<R: super::raw_carrier::RawBacking>(
        &mut self,
        requests: &super::Requests,
        socket: &IoOwner<R>,
    ) {
        if self.common.is_none() {
            return;
        }
        let super::Requests::Common(requests) = requests;
        let shared = requests.as_ref().map(|req| req.5.clone());
        let is_udp = matches!(socket, IoOwner::Udp(_));
        self.carrier_switch = Some(Box::new(Port::new(
            shared,
            self.cover.appearance(),
            self.info.local_addr,
            self.info.peer_addr,
            is_udp,
        )));
    }

    pub(super) fn carrier_switch_snapshot(&self) -> Option<CarrierSwitchSnapshot> {
        self.carrier_switch.as_deref().map(Port::snapshot)
    }

    pub(super) fn carrier_switch_wake(&self, now: u64) -> Option<u64> {
        self.carrier_switch.as_deref()?.wake_at(now)
    }

    pub(super) async fn service_carrier_switch<R: super::raw_carrier::RawBacking>(
        &mut self,
        socket: &mut IoOwner<R>,
        now: u64,
        instant: Instant,
    ) -> io::Result<()> {
        let Some(mut port) = self.carrier_switch.take() else {
            return Ok(());
        };
        let result = self
            .drive_carrier_switch(&mut port, socket, now, instant)
            .await;
        self.carrier_switch = Some(port);
        result
    }

    async fn drive_carrier_switch<R: super::raw_carrier::RawBacking>(
        &mut self,
        port: &mut Port,
        socket: &mut IoOwner<R>,
        now: u64,
        instant: Instant,
    ) -> io::Result<()> {
        // 1. Check initiator / responder deadlines.
        if let Some(active) = &port.initiator
            && now >= active.deadline_us
        {
            let err = match active.phase {
                InitiatorPhase::Probing { .. } => CarrierSwitchError::ProbeFailed,
                _ => CarrierSwitchError::Timeout,
            };
            port.complete_initiator(Err(err));
        }
        if let Some(standby) = &port.responder
            && now >= standby.deadline_us
        {
            port.responder = None;
        }

        // 2. Dequeue a new local switch request (client/initiator only).
        if port.initiator.is_none()
            && let Some(shared) = port.shared.clone()
            && let Some((id, target)) = shared.take_queued()
        {
            if !port.is_udp || !matches!(socket, IoOwner::Udp(_)) {
                port.complete_initiator(Err(CarrierSwitchError::UnsupportedCarrier));
            } else if self.info.role != Role::Initiator {
                port.complete_initiator(Err(CarrierSwitchError::NotCoordinator));
            } else {
                let frame = WireFrame {
                    kind: KIND_PROPOSE,
                    target,
                    code: CODE_OK,
                    id,
                    port: 0,
                    token: [0_u8; 32],
                }
                .encode();
                port.initiator = Some(InitiatorActive {
                    id,
                    target,
                    deadline_us: now.saturating_add(DEADLINE_US),
                    phase: InitiatorPhase::Proposed {
                        frame,
                        submitted: false,
                    },
                });
            }
        }

        // 3. Submit outgoing initiator frames & drive standby UDP probing / commit swap.
        let mut early_packet: Option<Vec<u8>> = None;
        if let Some(active) = port.initiator.take() {
            let InitiatorActive {
                id,
                target,
                deadline_us,
                phase,
            } = active;
            match phase {
                InitiatorPhase::Proposed {
                    frame,
                    mut submitted,
                } => {
                    if !submitted {
                        let deadline = deadline_us.min(self.lease);
                        if self
                            .submit(
                                now,
                                self.records.control_scope(),
                                super::control::Body::ProfileControl {
                                    tag: super::control::ProfileTag::CarrierSwitchV1,
                                    bytes: &frame,
                                },
                                deadline,
                                true,
                            )?
                            .is_some()
                        {
                            submitted = true;
                        }
                    }
                    port.initiator = Some(InitiatorActive {
                        id,
                        target,
                        deadline_us,
                        phase: InitiatorPhase::Proposed { frame, submitted },
                    });
                }
                InitiatorPhase::Probing {
                    socket: standby,
                    local_addr,
                    peer_addr,
                    token,
                    mut last_probe_us,
                    mut seq,
                } => {
                    if last_probe_us == 0 || now.saturating_sub(last_probe_us) >= PROBE_INTERVAL_US
                    {
                        seq = seq.saturating_add(1);
                        if let Ok(probe) =
                            encode_probe(target, &token, true, PROBE_MAGIC_REQ, id, seq)
                        {
                            let _ = standby.try_send(&probe);
                            last_probe_us = now;
                        }
                    }
                    let mut buf = [0_u8; 256];
                    let mut verified = false;
                    for _ in 0..8 {
                        match standby.try_recv(&mut buf) {
                            Ok(n) => {
                                if decode_probe(
                                    target,
                                    &token,
                                    true,
                                    PROBE_MAGIC_ACK,
                                    id,
                                    &buf[..n],
                                ) {
                                    verified = true;
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let next_phase = if verified {
                        let commit_frame = WireFrame {
                            kind: KIND_COMMIT,
                            target,
                            code: CODE_OK,
                            id,
                            port: peer_addr.port(),
                            token,
                        }
                        .encode();
                        InitiatorPhase::Committing {
                            socket: standby,
                            local_addr,
                            peer_addr,
                            token,
                            commit_frame,
                            commit_submitted: false,
                        }
                    } else {
                        InitiatorPhase::Probing {
                            socket: standby,
                            local_addr,
                            peer_addr,
                            token,
                            last_probe_us,
                            seq,
                        }
                    };
                    port.initiator = Some(InitiatorActive {
                        id,
                        target,
                        deadline_us,
                        phase: next_phase,
                    });
                }
                InitiatorPhase::Committing {
                    socket: standby,
                    local_addr,
                    peer_addr,
                    token,
                    commit_frame,
                    mut commit_submitted,
                } => {
                    if !commit_submitted {
                        let deadline = deadline_us.min(self.lease);
                        if self
                            .submit(
                                now,
                                self.records.control_scope(),
                                super::control::Body::ProfileControl {
                                    tag: super::control::ProfileTag::CarrierSwitchV1,
                                    bytes: &commit_frame,
                                },
                                deadline,
                                true,
                            )?
                            .is_some()
                        {
                            commit_submitted = true;
                        }
                    }
                    let mut buf = [0_u8; 2048];
                    let mut swap_now = false;
                    for _ in 0..8 {
                        match standby.try_recv(&mut buf) {
                            Ok(n) => {
                                if decode_probe(
                                    target,
                                    &token,
                                    true,
                                    PROBE_MAGIC_COMMIT,
                                    id,
                                    &buf[..n],
                                ) {
                                    swap_now = true;
                                    break;
                                }
                                // Ignore any late L2CA probe ack; any real Common record on the
                                // standby socket proves the responder has already swapped.
                                if !decode_probe(
                                    target,
                                    &token,
                                    true,
                                    PROBE_MAGIC_ACK,
                                    id,
                                    &buf[..n],
                                ) {
                                    early_packet = Some(buf[..n].to_vec());
                                    swap_now = true;
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    if swap_now {
                        let new_udp = UdpIo::new(standby);
                        self.credit_mark_buffers_dirty();
                        self.credit_observe_udp(&new_udp)?;
                        *socket = IoOwner::Udp(new_udp);
                        port.effective_cover = target.appearance();
                        port.local_addr = local_addr;
                        port.peer_addr = peer_addr;
                        port.switches = port.switches.saturating_add(1);
                        if let Some(runtime) = self.common.as_deref_mut() {
                            runtime.observation_dirty = true;
                        }
                        let outcome = CarrierSwitchOutcome {
                            target,
                            local_addr,
                            peer_addr,
                            switches: port.switches,
                        };
                        port.complete_initiator(Ok(outcome));
                    } else {
                        port.initiator = Some(InitiatorActive {
                            id,
                            target,
                            deadline_us,
                            phase: InitiatorPhase::Committing {
                                socket: standby,
                                local_addr,
                                peer_addr,
                                token,
                                commit_frame,
                                commit_submitted,
                            },
                        });
                    }
                }
            }
        }

        // If a Common packet arrived on the initiator's standby socket right after the
        // responder swapped, feed it immediately so zero packets are dropped.
        if let Some(packet) = early_packet {
            self.receive_selected_with_arrival(&packet, now, now, instant, instant)?;
        }

        // 4. Drive responder standby probing & commit swap.
        if let Some(mut standby) = port.responder.take() {
            let mut buf = [0_u8; 256];
            for _ in 0..8 {
                match standby.socket.try_recv_from(&mut buf) {
                    Ok((n, from)) => {
                        if decode_probe(
                            standby.target,
                            &standby.token,
                            false,
                            PROBE_MAGIC_REQ,
                            standby.id,
                            &buf[..n],
                        ) {
                            standby.peer_addr = Some(from);
                            standby.seq = standby.seq.saturating_add(1);
                            if let Ok(ack) = encode_probe(
                                standby.target,
                                &standby.token,
                                false,
                                PROBE_MAGIC_ACK,
                                standby.id,
                                standby.seq,
                            ) {
                                let _ = standby.socket.try_send_to(&ack, from);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            if standby.commit_pending
                && let Some(peer) = standby.peer_addr
            {
                standby.socket.connect(peer).await?;
                standby.seq = standby.seq.saturating_add(1);
                if let Ok(confirm) = encode_probe(
                    standby.target,
                    &standby.token,
                    false,
                    PROBE_MAGIC_COMMIT,
                    standby.id,
                    standby.seq,
                ) {
                    // Send two quick copies so a single packet drop doesn't wait for reliable CommitAck.
                    let _ = standby.socket.try_send(&confirm);
                    let _ = standby.socket.try_send(&confirm);
                }
                let new_udp = UdpIo::new(standby.socket);
                self.credit_mark_buffers_dirty();
                self.credit_observe_udp(&new_udp)?;
                *socket = IoOwner::Udp(new_udp);
                port.effective_cover = standby.target.appearance();
                port.local_addr = standby.local_addr;
                port.peer_addr = peer;
                port.switches = port.switches.saturating_add(1);
                if let Some(runtime) = self.common.as_deref_mut() {
                    runtime.observation_dirty = true;
                }
                let ack_frame = WireFrame {
                    kind: KIND_COMMIT_ACK,
                    target: standby.target,
                    code: CODE_OK,
                    id: standby.id,
                    port: standby.local_addr.port(),
                    token: standby.token,
                }
                .encode();
                port.push_outgoing(ack_frame, now.saturating_add(DEADLINE_US));
            } else {
                port.responder = Some(standby);
            }
        }

        // 5. Flush queued outgoing responder frames over the authenticated Control stream.
        while let Some((frame, deadline_us)) = port.outgoing.pop_front() {
            if now >= deadline_us {
                continue;
            }
            let deadline = deadline_us.min(self.lease);
            let submitted = self.submit(
                now,
                self.records.control_scope(),
                super::control::Body::ProfileControl {
                    tag: super::control::ProfileTag::CarrierSwitchV1,
                    bytes: &frame,
                },
                deadline,
                true,
            )?;
            if submitted.is_none() {
                port.outgoing.push_front((frame, deadline_us));
                break;
            }
        }
        Ok(())
    }

    pub(super) fn receive_carrier_switch(&mut self, now: u64, bytes: &[u8]) -> io::Result<()> {
        let Some(mut port) = self.carrier_switch.take() else {
            return Ok(());
        };
        let deadline_us = now.saturating_add(DEADLINE_US);
        let Some(frame) = WireFrame::decode(bytes) else {
            if port.initiator.is_some() {
                port.complete_initiator(Err(CarrierSwitchError::Malformed));
            }
            self.carrier_switch = Some(port);
            return Ok(());
        };
        match frame.kind {
            KIND_PROPOSE => {
                if !port.is_udp {
                    let refuse = WireFrame {
                        kind: KIND_REFUSE,
                        code: CODE_UNSUPPORTED,
                        ..frame
                    }
                    .encode();
                    port.push_outgoing(refuse, deadline_us);
                } else if port.responder.is_some() {
                    let refuse = WireFrame {
                        kind: KIND_REFUSE,
                        code: CODE_BUSY,
                        ..frame
                    }
                    .encode();
                    port.push_outgoing(refuse, deadline_us);
                } else {
                    match (bind_standby_udp(port.local_addr.ip()), random_token()) {
                        (Ok((sock, local_addr)), Ok(token)) => {
                            let ready = WireFrame {
                                kind: KIND_READY,
                                target: frame.target,
                                code: CODE_OK,
                                id: frame.id,
                                port: local_addr.port(),
                                token,
                            }
                            .encode();
                            port.responder = Some(ResponderStandby {
                                id: frame.id,
                                target: frame.target,
                                socket: sock,
                                local_addr,
                                peer_addr: None,
                                token,
                                deadline_us,
                                commit_pending: false,
                                seq: 0,
                            });
                            port.push_outgoing(ready, deadline_us);
                        }
                        _ => {
                            let refuse = WireFrame {
                                kind: KIND_REFUSE,
                                code: CODE_BIND_FAILED,
                                ..frame
                            }
                            .encode();
                            port.push_outgoing(refuse, deadline_us);
                        }
                    }
                }
            }
            KIND_READY => {
                if let Some(active) = &mut port.initiator
                    && active.id == frame.id
                    && active.target == frame.target
                    && matches!(active.phase, InitiatorPhase::Proposed { .. })
                {
                    if frame.port == 0 {
                        port.complete_initiator(Err(CarrierSwitchError::Malformed));
                    } else {
                        let peer_addr = SocketAddr::new(port.peer_addr.ip(), frame.port);
                        match bind_connected_standby_udp(port.local_addr.ip(), peer_addr) {
                            Ok((sock, local_addr)) => {
                                active.phase = InitiatorPhase::Probing {
                                    socket: sock,
                                    local_addr,
                                    peer_addr,
                                    token: frame.token,
                                    last_probe_us: 0,
                                    seq: 0,
                                };
                            }
                            Err(_) => {
                                port.complete_initiator(Err(CarrierSwitchError::BindFailed));
                            }
                        }
                    }
                }
            }
            KIND_COMMIT => {
                if let Some(standby) = &mut port.responder
                    && standby.id == frame.id
                    && standby.target == frame.target
                    && constant_time_eq(&standby.token, &frame.token)
                    && standby.peer_addr.is_some()
                {
                    standby.commit_pending = true;
                } else {
                    let refuse = WireFrame {
                        kind: KIND_REFUSE,
                        code: CODE_INVALID,
                        ..frame
                    }
                    .encode();
                    port.push_outgoing(refuse, deadline_us);
                }
            }
            KIND_COMMIT_ACK => {
                // CommitAck on the reliable Control stream acts as an additional
                // acknowledgement if L2CK was not already observed.
                if let Some(active) = &port.initiator
                    && active.id == frame.id
                    && active.target == frame.target
                {
                    // Swap already happened on L2CK/first standby packet; nothing more needed.
                }
            }
            KIND_REFUSE => {
                if port.initiator.as_ref().is_some_and(|a| a.id == frame.id) {
                    let err = match frame.code {
                        CODE_UNSUPPORTED => CarrierSwitchError::UnsupportedCarrier,
                        CODE_BUSY => CarrierSwitchError::Busy,
                        CODE_BIND_FAILED => CarrierSwitchError::BindFailed,
                        _ => CarrierSwitchError::PeerRefused,
                    };
                    port.complete_initiator(Err(err));
                }
            }
            _ => {}
        }
        self.carrier_switch = Some(port);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_frame_round_trips_and_rejects_bad_inputs() {
        let token = [0x5a_u8; 32];
        let frame = WireFrame {
            kind: KIND_READY,
            target: CarrierTarget::UdpMediaLike,
            code: CODE_OK,
            id: 7,
            port: 51900,
            token,
        };
        let encoded = frame.encode();
        assert_eq!(encoded.len(), FRAME_BYTES);
        assert_eq!(WireFrame::decode(&encoded), Some(frame));

        let mut bad_ver = encoded;
        bad_ver[0] = 2;
        assert_eq!(WireFrame::decode(&bad_ver), None);

        let mut bad_reserved = encoded;
        bad_reserved[55] = 1;
        assert_eq!(WireFrame::decode(&bad_reserved), None);

        let mut bad_id = encoded;
        bad_id[4..8].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(WireFrame::decode(&bad_id), None);
    }

    #[test]
    fn cover_probes_encode_and_verify_for_every_udp_cover() -> io::Result<()> {
        let token = [0x3c_u8; 32];
        for target in [
            CarrierTarget::UdpQuicLike,
            CarrierTarget::UdpMediaLike,
            CarrierTarget::UdpTlsLike,
        ] {
            let req = encode_probe(target, &token, true, PROBE_MAGIC_REQ, 11, 1)?;
            assert!(decode_probe(
                target,
                &token,
                false,
                PROBE_MAGIC_REQ,
                11,
                &req
            ));
            assert!(!decode_probe(
                target,
                &token,
                false,
                PROBE_MAGIC_REQ,
                12,
                &req
            ));
            assert!(!decode_probe(
                target,
                &[0x99; 32],
                false,
                PROBE_MAGIC_REQ,
                11,
                &req
            ));

            let ack = encode_probe(target, &token, false, PROBE_MAGIC_ACK, 11, 1)?;
            assert!(decode_probe(
                target,
                &token,
                true,
                PROBE_MAGIC_ACK,
                11,
                &ack
            ));
        }
        Ok(())
    }
}

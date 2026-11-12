//! Bounded initial-SYN policy and authenticated remote reservation before local ACK.
//!
//! This single-flow primitive needs a previously authenticated reliable ordered
//! carrier. It provides no native dispatcher, route authorization or fallback table.
use super::{Config, Leg, Millis, Role, Scope, TcpIpConfig, TcpStatus};
use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv6Packet, TcpOption, TcpPacket};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

const HEADER: usize = 40;
const MAX_SYN: usize = 100;

/// A valid packet that must remain in its original transparent flow from the start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bypass {
    /// This is not an initial TCP SYN.
    NotInitialSyn,
    /// IP options, extensions, fragments or a non-TCP next header are unsupported.
    IpProfile,
    /// Address/port is unsuitable for the maintained fixed-tuple proxy.
    Address,
    /// SYN payload, including Fast Open data, must not be locally acknowledged here.
    SynData,
    /// ECN/NS/urgent or other nonplain SYN flags need a separate option policy.
    Flags,
    /// Unknown or protected TCP option; preserve the complete original flow.
    Option(u8),
    /// Repeated or unsuitable standard option cannot be safely normalized.
    OptionPolicy,
}

/// Result of inspection; only Candidate allocates bounded original packet bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Inspection {
    /// Eligible only after explicit route opt-in and authenticated reservation.
    Candidate(InitialSyn),
    /// Leave original bytes and ownership unchanged.
    Bypass(Bypass),
}

/// Validated original initial SYN, constructed only by the strict inspector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialSyn {
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    dscp: u8,
    bytes: Vec<u8>,
}
impl InitialSyn {
    /// Original source; retained at the far proxy's native TCP leg.
    pub fn source(&self) -> SocketAddr {
        self.source
    }
    /// Original destination; retained at the near proxy's native TCP leg.
    pub fn destination(&self) -> SocketAddr {
        self.destination
    }
    /// Original sender's sequence number; independent from the far TCP leg.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    /// Untrusted DSCP to which the session's policy may assign a weight.
    pub fn dscp(&self) -> u8 {
        self.dscp
    }
    /// Exact original header bytes; never an acknowledged payload.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Inspection, transaction or underlying bounded relay failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Invalid packet/configuration/time interval bounds.
    Bounds,
    /// Noncanonical or truncated IP/TCP/admission frame.
    Malformed,
    /// Original IP/TCP checksum is invalid.
    Checksum,
    /// Wrong authenticated session, epoch or flow.
    Scope,
    /// Native tuple would change original source/destination ownership.
    Tuple,
    /// Open proposed a packet outside the explicit proxy admission profile.
    Unsupported,
    /// Wrong phase or no retained admission output/active leg.
    State,
    /// Injected time regressed or deadline arithmetic overflowed.
    Time,
    /// Original fixed admission deadline expired; reservations are released.
    Expired,
    /// Maintained relay construction/admission failed.
    Relay(super::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "TCP proxy admission: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Relay(error)
    }
}

fn usable(address: SocketAddr) -> bool {
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return false;
    }
    match address {
        SocketAddr::V4(value) => !value.ip().is_broadcast(),
        SocketAddr::V6(value) => {
            value.scope_id() == 0
                && value.flowinfo() == 0
                && !value.ip().is_unicast_link_local()
                && value.ip().to_ipv4_mapped().is_none()
        }
    }
}

/// Inspect complete native IP bytes without changing either endpoint's TCP state.
/// The caller must keep every Bypass flow transparent for its complete lifetime.
pub fn inspect_syn(bytes: &[u8], max_packet_bytes: usize) -> Result<Inspection, Error> {
    if !(40..=65_535).contains(&max_packet_bytes) || bytes.len() > max_packet_bytes {
        return Err(Error::Bounds);
    }
    let (source, destination, payload, dscp, ecn) = match bytes.first().map(|byte| byte >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(bytes).map_err(|_| Error::Malformed)?;
            if usize::from(ip.total_len()) != bytes.len() {
                return Err(Error::Malformed);
            }
            if !ip.verify_checksum() {
                return Err(Error::Checksum);
            }
            if ip.header_len() != 20
                || ip.more_frags()
                || ip.frag_offset() != 0
                || ip.next_header() != IpProtocol::Tcp
            {
                return Ok(Inspection::Bypass(Bypass::IpProfile));
            }
            (
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                &bytes[20..],
                ip.dscp(),
                ip.ecn(),
            )
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(bytes).map_err(|_| Error::Malformed)?;
            if usize::from(ip.payload_len()) + 40 != bytes.len() {
                return Err(Error::Malformed);
            }
            if ip.payload_len() == 0 || ip.next_header() != IpProtocol::Tcp {
                return Ok(Inspection::Bypass(Bypass::IpProfile));
            }
            (
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                &bytes[40..],
                ip.traffic_class() >> 2,
                ip.traffic_class() & 3,
            )
        }
        _ => return Err(Error::Malformed),
    };
    let tcp = TcpPacket::new_checked(payload).map_err(|_| Error::Malformed)?;
    if !tcp.verify_checksum(&IpAddress::from(source), &IpAddress::from(destination)) {
        return Err(Error::Checksum);
    }
    if !tcp.syn() || tcp.ack() {
        return Ok(Inspection::Bypass(Bypass::NotInitialSyn));
    }
    if payload[12] & 15 != 0 || payload[13] != 2 || ecn != 0 {
        return Ok(Inspection::Bypass(Bypass::Flags));
    }
    if !tcp.payload().is_empty() {
        return Ok(Inspection::Bypass(Bypass::SynData));
    }
    let source = SocketAddr::new(source, tcp.src_port());
    let destination = SocketAddr::new(destination, tcp.dst_port());
    if !usable(source) || !usable(destination) || source == destination {
        return Ok(Inspection::Bypass(Bypass::Address));
    }
    let mut options = tcp.options();
    let mut seen = 0u8;
    while !options.is_empty() {
        let (rest, option) = TcpOption::parse(options).map_err(|_| Error::Malformed)?;
        let bit = match option {
            TcpOption::EndOfList => {
                if rest.iter().any(|byte| *byte != 0) {
                    return Ok(Inspection::Bypass(Bypass::OptionPolicy));
                }
                break;
            }
            TcpOption::NoOperation => 0,
            TcpOption::MaxSegmentSize(value) if value != 0 => 1,
            TcpOption::WindowScale(value) if value <= 14 => 2,
            TcpOption::SackPermitted => 4,
            TcpOption::TimeStamp { tsecr: 0, .. } => 8,
            TcpOption::Unknown { kind, .. } => return Ok(Inspection::Bypass(Bypass::Option(kind))),
            _ => return Ok(Inspection::Bypass(Bypass::OptionPolicy)),
        };
        if seen & bit != 0 {
            return Ok(Inspection::Bypass(Bypass::OptionPolicy));
        }
        seen |= bit;
        options = rest;
    }
    if bytes.len() > MAX_SYN {
        return Err(Error::Bounds);
    }
    Ok(Inspection::Candidate(InitialSyn {
        source,
        destination,
        sequence: tcp.seq_number().0 as u32,
        dscp,
        bytes: bytes.to_vec(),
    }))
}

/// Native TCP is inaccessible until the reservation and actual carrier handoff finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Retaining original Open until reliable-carrier ownership.
    SendingOpen,
    /// Awaiting authenticated peer reservation.
    AwaitingReady,
    /// Retaining Ready before peer may commit.
    SendingReady,
    /// Peer has the reservation but has not committed ownership.
    AwaitingCommit,
    /// Commit is retained; local SYN is still not admitted.
    SendingCommit,
    /// Reserved maintained leg may be taken exactly once.
    Active,
    /// The caller now owns the active leg.
    Taken,
    /// Deadline failure released the unpolled reservation.
    Failed,
}

/// A single bounded reservation; a session manager must separately bound flow count.
pub struct Opening {
    scope: Scope,
    phase: Phase,
    leg: Option<Leg>,
    syn: Option<InitialSyn>,
    output: Option<Vec<u8>>,
    last: Millis,
    deadline: Millis,
}
impl Opening {
    /// Reserve local memory without ingesting SYN or producing SYN-ACK.
    pub fn local(
        config: Config,
        native: TcpIpConfig,
        syn: InitialSyn,
        now: Millis,
        timeout_ms: u64,
    ) -> Result<Self, Error> {
        let deadline = deadline(now, timeout_ms)?;
        if native.local != syn.destination || native.peer != syn.source {
            return Err(Error::Tuple);
        }
        let leg = Leg::new_ip(config, native, Role::Server, now)?;
        let mut output = encode(config.scope, 1);
        output.extend_from_slice(&(syn.bytes.len() as u16).to_be_bytes());
        output.extend_from_slice(&syn.bytes);
        Ok(Self {
            scope: config.scope,
            phase: Phase::SendingOpen,
            leg: Some(leg),
            syn: Some(syn),
            output: Some(output),
            last: now,
            deadline,
        })
    }
    /// Reserve the far maintained leg after authenticated route/flow authorization.
    /// No remote SYN is emitted until the returned active leg is taken and polled.
    pub fn remote(
        config: Config,
        native: TcpIpConfig,
        open: &[u8],
        now: Millis,
        timeout_ms: u64,
    ) -> Result<Self, Error> {
        let deadline = deadline(now, timeout_ms)?;
        let syn = inspect_open(config.scope, open)?;
        if native.local != syn.source || native.peer != syn.destination {
            return Err(Error::Tuple);
        }
        let leg = Leg::new_ip(config, native, Role::Client, now)?;
        Ok(Self {
            scope: config.scope,
            phase: Phase::SendingReady,
            leg: Some(leg),
            syn: None,
            output: Some(encode(config.scope, 2)),
            last: now,
            deadline,
        })
    }
    /// Select an explicit native close policy while the reserved leg is unpolled.
    pub fn set_time_wait_reset_policy(
        &mut self,
        policy: super::TimeWaitResetPolicy,
    ) -> Result<(), Error> {
        if !matches!(self.phase, Phase::SendingOpen | Phase::SendingReady) {
            return Err(Error::State);
        }
        self.leg
            .as_mut()
            .ok_or(Error::State)?
            .set_time_wait_reset_policy(policy)?;
        Ok(())
    }
    /// Current ownership phase, with no network progress implied.
    pub fn phase(&self) -> Phase {
        self.phase
    }
    /// Fixed original admission deadline; never extended by peer traffic.
    pub fn deadline(&self) -> Millis {
        self.deadline
    }
    /// Inspect actual unpolled maintained queues without exposing native TCP I/O.
    pub fn native_status(&self) -> Option<TcpStatus> {
        self.leg.as_ref().map(|leg| leg.status().native)
    }
    /// Borrow immutable bytes; the caller retains ownership across carrier backpressure.
    pub fn pending_record(&self) -> Option<&[u8]> {
        self.output.as_deref()
    }
    /// Advance only after the reliable carrier owns the exact retained record.
    pub fn confirm_record_sent(&mut self, now: Millis) -> Result<(), Error> {
        self.tick(now)?;
        if self.output.is_none() {
            return Err(Error::State);
        }
        let next = match self.phase {
            Phase::SendingOpen => Phase::AwaitingReady,
            Phase::SendingReady => Phase::AwaitingCommit,
            Phase::SendingCommit => {
                let syn = self.syn.as_ref().ok_or(Error::State)?;
                self.leg
                    .as_mut()
                    .ok_or(Error::State)?
                    .ingest_packet(&syn.bytes)?;
                self.syn = None;
                Phase::Active
            }
            _ => return Err(Error::State),
        };
        self.output = None;
        self.phase = next;
        Ok(())
    }
    /// Process one already authenticated, framed and ordered admission message.
    pub fn receive_authenticated(&mut self, bytes: &[u8], now: Millis) -> Result<(), Error> {
        self.tick(now)?;
        let (kind, _) = decode(self.scope, bytes)?;
        match (self.phase, kind) {
            (Phase::AwaitingReady, 2) => {
                self.output = Some(encode(self.scope, 3));
                self.phase = Phase::SendingCommit;
            }
            (Phase::AwaitingCommit, 3) => self.phase = Phase::Active,
            _ => return Err(Error::State),
        }
        Ok(())
    }
    /// Transfer the maintained relay exactly once after the reservation barrier.
    pub fn take_leg(&mut self, now: Millis) -> Result<Leg, Error> {
        self.tick(now)?;
        if self.phase != Phase::Active {
            return Err(Error::State);
        }
        let leg = self.leg.take().ok_or(Error::State)?;
        self.phase = Phase::Taken;
        Ok(leg)
    }
    /// Apply monotonic time and terminal expiry without polling native TCP.
    pub fn tick(&mut self, now: Millis) -> Result<(), Error> {
        if self.phase == Phase::Failed {
            return Err(Error::Expired);
        }
        if self.phase == Phase::Taken {
            return Err(Error::State);
        }
        if now < self.last {
            return Err(Error::Time);
        }
        if now >= self.deadline {
            self.phase = Phase::Failed;
            self.leg = None;
            self.output = None;
            self.syn = None;
            return Err(Error::Expired);
        }
        self.last = now;
        Ok(())
    }
}
fn deadline(now: Millis, timeout: u64) -> Result<Millis, Error> {
    if !(1..=120_000).contains(&timeout) {
        return Err(Error::Bounds);
    }
    now.0.checked_add(timeout).map(Millis).ok_or(Error::Time)
}
fn encode(scope: Scope, kind: u8) -> Vec<u8> {
    let mut bytes = vec![0; HEADER];
    bytes[..4].copy_from_slice(b"LTPA");
    bytes[4] = 1;
    bytes[5] = kind;
    bytes[8..24].copy_from_slice(&scope.session);
    bytes[24..32].copy_from_slice(&scope.epoch.to_be_bytes());
    bytes[32..40].copy_from_slice(&scope.flow.to_be_bytes());
    bytes
}
/// Inspect an authenticated Open for route authorization without reserving a leg.
///
/// The enclosing caller must already verify member identity, reliable ordered
/// delivery and its outer flow/session scope. This function validates exact
/// admission framing and the complete original SYN; it grants no route permission,
/// consumes no replay state and cannot itself acknowledge the original sender.
pub fn inspect_open(scope: Scope, bytes: &[u8]) -> Result<InitialSyn, Error> {
    let (kind, body) = decode(scope, bytes)?;
    if kind != 1 {
        return Err(Error::State);
    }
    match inspect_syn(body, MAX_SYN)? {
        Inspection::Candidate(syn) => Ok(syn),
        Inspection::Bypass(_) => Err(Error::Unsupported),
    }
}

pub(super) fn decode(scope: Scope, bytes: &[u8]) -> Result<(u8, &[u8]), Error> {
    if bytes.len() < HEADER
        || bytes.len() > HEADER + 2 + MAX_SYN
        || &bytes[..4] != b"LTPA"
        || bytes[4] != 1
        || bytes[6..8] != [0, 0]
    {
        return Err(Error::Malformed);
    }
    if bytes[8..24] != scope.session
        || bytes[24..32] != scope.epoch.to_be_bytes()
        || bytes[32..40] != scope.flow.to_be_bytes()
    {
        return Err(Error::Scope);
    }
    match bytes[5] {
        1 if bytes.len() >= HEADER + 2 => {
            let length = usize::from(u16::from_be_bytes([bytes[40], bytes[41]]));
            if !(40..=MAX_SYN).contains(&length) || bytes.len() != HEADER + 2 + length {
                return Err(Error::Malformed);
            }
            Ok((1, &bytes[42..]))
        }
        kind @ (2 | 3) if bytes.len() == HEADER => Ok((kind, &[])),
        _ => Err(Error::Malformed),
    }
}

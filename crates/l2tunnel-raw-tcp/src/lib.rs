//! Bounded userspace TCP stream owner; native raw adapters are a separate boundary.
//!
//! One maintained smoltcp socket owns a fixed IP four-tuple. The caller supplies
//! time and complete raw IP packets, retains emitted packets across I/O pressure,
//! and supplies an unpredictable initial seed. No socket, clock, TLS, packet-phase
//! transition or kernel RST rule is implemented by this pure crate.
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket,
};
use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};

/// Opt-in checked stream ownership and logical quiescent consume capability.
pub mod handoff;
/// Bounded IPv4/TCP packet inspection and emission using the maintained wire codec.
pub mod packet;

/// Maintained TCP state; independent from authenticated tunnel session state.
pub use smoltcp::socket::tcp::State;

/// Caller-injected monotonic milliseconds, with checked conversion to stack time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Millis(pub u64);
/// Which endpoint initiates the maintained TCP three-way handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Initiate one connection to the exact configured peer.
    Client,
    /// Listen only for the exact configured peer tuple.
    Server,
}
/// Finite immutable dimensions for a single raw-owned TCP stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config<A = SocketAddrV4> {
    /// Local explicit unicast IP address and nonzero TCP port; IPv4 by default.
    pub local: A,
    /// Exact authorized address/port for packet admission, before TLS authentication.
    pub peer: A,
    /// Whole IP packet ceiling; no IP fragmentation is accepted.
    pub mtu: usize,
    /// Maintained TCP send ring, including unacknowledged bytes.
    pub send_bytes: usize,
    /// Maintained TCP receive ring, including unread bytes.
    pub receive_bytes: usize,
    /// Maximum raw IP packets in each inbound/outbound queue.
    pub packet_slots: usize,
    /// Caller-provided unpredictable nonzero per-instance seed; never a traffic key.
    pub random_seed: u64,
    /// Bounded delayed ACK interval; zero selects immediate ACK policy.
    pub ack_delay_millis: u64,
    /// Positive maintained keepalive spacing, below the idle timeout.
    pub keepalive_millis: u64,
    /// Connect/peer-liveness timeout; keepalive makes idle loss observable.
    pub idle_timeout_millis: u64,
}
/// Explicit IPv4 or IPv6 same-family tuple; scoped/mapped IPv6 is unsupported.
pub type IpConfig = Config<SocketAddr>;

impl From<Config> for IpConfig {
    fn from(value: Config) -> Self {
        Self {
            local: value.local.into(),
            peer: value.peer.into(),
            mtu: value.mtu,
            send_bytes: value.send_bytes,
            receive_bytes: value.receive_bytes,
            packet_slots: value.packet_slots,
            random_seed: value.random_seed,
            ack_delay_millis: value.ack_delay_millis,
            keepalive_millis: value.keepalive_millis,
            idle_timeout_millis: value.idle_timeout_millis,
        }
    }
}
/// Checked construction, admission or stream failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Unsupported address, zero/inconsistent/excessive resource limit or timing.
    InvalidConfig,
    /// Injected time moved backwards or exceeded safe stack timer arithmetic.
    Time,
    /// Zero or excessive caller polling work allowance.
    WorkLimit,
    /// Invalid IP/TCP length, version, options profile or fragmentation.
    Malformed,
    /// IP/TCP checksum verification failed before state admission.
    Checksum,
    /// Packet does not belong to the exact configured incoming four-tuple.
    Tuple,
    /// Packet exceeds the configured path MTU.
    Mtu,
    /// Bounded incoming queue cannot accept another packet; state is unchanged.
    QueueFull,
    /// TCP is not in a state that accepts stream writes.
    NotConnected,
    /// The caller provided an empty receive buffer.
    EmptyBuffer,
    /// Maintained-stack setup failed despite prevalidated configuration.
    Stack,
    /// Connection terminated without an orderly fully retained receive stream.
    Terminated(CloseReason),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "raw TCP stream: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Read result separates current backpressure from a fully consumed peer EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    /// Original ordered stream bytes copied into the caller's buffer.
    Data(usize),
    /// No bytes are currently available; handshake/open stream may still progress.
    Pending,
    /// Accepted peer FIN ended the receive half and no buffered bytes remain.
    Eof,
}

/// Public-state close outcome; no private maintained TCP fields are inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    /// Accepted final ACK or maintained TimeWait expiry completed both FIN halves.
    Clean,
    /// An accepted incoming RST closed the maintained connection.
    PeerReset,
    /// Maintained handshake/peer-liveness timeout closed the connection.
    Timeout,
    /// Local abort or close before connection establishment.
    LocalAbort,
    /// TimeWait expiry discarded unread maintained receive-ring bytes.
    UndrainedReceive,
    /// Unclassified maintained transition; never reported as clean completion.
    Unexpected,
}
/// Actual bounded queues and maintained stream state; no authentication claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Maintained TCP connection state.
    pub state: State,
    /// The maintained socket reached an established or post-established state.
    pub established: bool,
    /// A maintained transition proved that an in-sequence peer FIN was accepted.
    pub peer_fin: bool,
    /// Terminal reason, independent of whether native output has drained yet.
    pub close_reason: Option<CloseReason>,
    /// Raw packets retained before stack processing.
    pub incoming_packets: usize,
    /// Raw packets retained before caller/native transmission.
    pub outgoing_packets: usize,
    /// TCP stream bytes awaiting send/acknowledgment.
    pub send_bytes: usize,
    /// Received stream bytes awaiting caller consumption.
    pub receive_bytes: usize,
    /// Actual scaled maintained peer receive window; absent before establishment
    /// or after closed. This is native flow control, never endpoint cwnd.
    pub peer_receive_window_bytes: Option<usize>,
}

fn time(value: Millis) -> Result<Instant, Error> {
    // Leave room for every configured timer before converting ms to stack us.
    if value.0 > (i64::MAX as u64 / 1000).saturating_sub(300_000) {
        return Err(Error::Time);
    }
    Ok(Instant::from_millis(value.0 as i64))
}
impl IpConfig {
    /// Validate finite tuple, ring, packet and timing bounds without allocation.
    pub fn validate(self) -> Result<(), Error> {
        for address in [self.local, self.peer] {
            if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                return Err(Error::InvalidConfig);
            }
            match address {
                SocketAddr::V4(value) if value.ip().is_broadcast() => {
                    return Err(Error::InvalidConfig);
                }
                SocketAddr::V6(value)
                    if value.scope_id() != 0
                        || value.flowinfo() != 0
                        || value.ip().is_unicast_link_local()
                        || value.ip().to_ipv4_mapped().is_some() =>
                {
                    return Err(Error::InvalidConfig);
                }
                _ => {}
            }
        }
        let minimum_mtu = if self.local.is_ipv6() { 1280 } else { 576 };
        if self.local == self.peer
            || self.local.is_ipv4() != self.peer.is_ipv4()
            || !(minimum_mtu..=65_535).contains(&self.mtu)
            || !(self.mtu..=4_194_304).contains(&self.send_bytes)
            || !(self.mtu..=4_194_304).contains(&self.receive_bytes)
            || !(1..=1024).contains(&self.packet_slots)
            || self.random_seed == 0
            || self.ack_delay_millis > 200
            || self.keepalive_millis == 0
            || !(1_000..=120_000).contains(&self.idle_timeout_millis)
            || self.keepalive_millis >= self.idle_timeout_millis
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }
    fn validate_packet(self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.mtu {
            return Err(Error::Mtu);
        }
        let (source, destination, payload) = match bytes.first().map(|byte| byte >> 4) {
            Some(4) if self.local.is_ipv4() => {
                let ip = Ipv4Packet::new_checked(bytes).map_err(|_| Error::Malformed)?;
                if usize::from(ip.total_len()) != bytes.len()
                    || ip.header_len() != 20
                    || ip.more_frags()
                    || ip.frag_offset() != 0
                    || ip.next_header() != IpProtocol::Tcp
                {
                    return Err(Error::Malformed);
                }
                if IpAddr::V4(ip.src_addr()) != self.peer.ip()
                    || IpAddr::V4(ip.dst_addr()) != self.local.ip()
                {
                    return Err(Error::Tuple);
                }
                if !ip.verify_checksum() {
                    return Err(Error::Checksum);
                }
                (
                    IpAddress::Ipv4(ip.src_addr()),
                    IpAddress::Ipv4(ip.dst_addr()),
                    &bytes[20..],
                )
            }
            Some(6) if self.local.is_ipv6() => {
                let ip = Ipv6Packet::new_checked(bytes).map_err(|_| Error::Malformed)?;
                if ip.payload_len() == 0
                    || usize::from(ip.payload_len()) + 40 != bytes.len()
                    || ip.next_header() != IpProtocol::Tcp
                {
                    return Err(Error::Malformed);
                }
                if IpAddr::V6(ip.src_addr()) != self.peer.ip()
                    || IpAddr::V6(ip.dst_addr()) != self.local.ip()
                {
                    return Err(Error::Tuple);
                }
                (
                    IpAddress::Ipv6(ip.src_addr()),
                    IpAddress::Ipv6(ip.dst_addr()),
                    &bytes[40..],
                )
            }
            Some(4 | 6) => return Err(Error::Tuple),
            _ => return Err(Error::Malformed),
        };
        let segment = TcpPacket::new_checked(payload).map_err(|_| Error::Malformed)?;
        if segment.src_port() != self.peer.port() || segment.dst_port() != self.local.port() {
            return Err(Error::Tuple);
        }
        if !segment.verify_checksum(&source, &destination) {
            return Err(Error::Checksum);
        }
        Ok(())
    }
}

struct Queues {
    incoming: VecDeque<Vec<u8>>,
    outgoing: VecDeque<Vec<u8>>,
    mtu: usize,
    slots: usize,
}
struct Rx(Vec<u8>);
impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // The maintained IP-medium stack supplies a complete frame within its
        // declared MTU; acquiring this token already reserved one queue slot.
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}
impl Device for Queues {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.outgoing.len() >= self.slots {
            return None;
        }
        let packet = self.incoming.pop_front()?;
        Some((Rx(packet), Tx(&mut self.outgoing)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        if self.outgoing.len() >= self.slots {
            return None;
        }
        Some(Tx(&mut self.outgoing))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(self.slots);
        caps
    }
}

/// One fixed-tuple TCP engine with finite owned rings and raw packet queues.
pub struct TcpEngine {
    config: IpConfig,
    interface: Interface,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    queues: Queues,
    last_time: Millis,
    ever_connected: bool,
    peer_fin: bool,
    close_reason: Option<CloseReason>,
    time_wait_reset_policy: TimeWaitResetPolicy,
    polled: bool,
}

/// Explicit TIME-WAIT reset handling; all other TCP state remains maintained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TimeWaitResetPolicy {
    /// Preserve the pinned stack's accepted-RST behavior (RFC 9293).
    #[default]
    Maintained,
    /// Drop validated RST only in actual TIME-WAIT, following RFC 1337 F1.
    /// The pinned stack's timer is unchanged; this is not full RFC 1337 qualification.
    IgnoreInTimeWait,
}
impl TcpEngine {
    /// Validate before allocation and start one maintained client/listener socket.
    pub fn new(config: Config, role: Role, now: Millis) -> Result<Self, Error> {
        Self::new_ip(config.into(), role, now)
    }
    /// Start an explicit IPv4/IPv6 fixed tuple; extensions/fragments are unsupported.
    pub fn new_ip(config: IpConfig, role: Role, now: Millis) -> Result<Self, Error> {
        config.validate()?;
        let instant = time(now)?;
        let mut queues = Queues {
            incoming: VecDeque::new(),
            outgoing: VecDeque::new(),
            mtu: config.mtu,
            slots: config.packet_slots,
        };
        let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
        interface_config.random_seed = config.random_seed;
        let mut interface = Interface::new(interface_config, &mut queues, instant);
        let mut address_ok = false;
        interface.update_ip_addrs(|addresses| {
            address_ok = addresses
                .push(IpCidr::new(
                    config.local.ip().into(),
                    if config.local.is_ipv4() { 32 } else { 128 },
                ))
                .is_ok();
        });
        if !address_ok {
            return Err(Error::Stack);
        }
        match config.peer.ip() {
            IpAddr::V4(address) => interface.routes_mut().add_default_ipv4_route(address),
            IpAddr::V6(address) => interface.routes_mut().add_default_ipv6_route(address),
        }
        .map_err(|_| Error::Stack)?;
        let mut endpoint = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; config.receive_bytes]),
            tcp::SocketBuffer::new(vec![0; config.send_bytes]),
        );
        endpoint.set_nagle_enabled(false);
        endpoint.set_ack_delay(
            (config.ack_delay_millis != 0).then(|| Duration::from_millis(config.ack_delay_millis)),
        );
        endpoint.set_keep_alive(Some(Duration::from_millis(config.keepalive_millis)));
        endpoint.set_timeout(Some(Duration::from_millis(config.idle_timeout_millis)));
        match role {
            Role::Client => endpoint
                .connect(
                    interface.context(),
                    (IpAddress::from(config.peer.ip()), config.peer.port()),
                    (IpAddress::from(config.local.ip()), config.local.port()),
                )
                .map_err(|_| Error::Stack)?,
            Role::Server => endpoint
                .listen((IpAddress::from(config.local.ip()), config.local.port()))
                .map_err(|_| Error::Stack)?,
        }
        let mut sockets = SocketSet::new(Vec::with_capacity(1));
        let socket = sockets.add(endpoint);
        Ok(Self {
            config,
            interface,
            sockets,
            socket,
            queues,
            last_time: now,
            ever_connected: false,
            peer_fin: false,
            close_reason: None,
            time_wait_reset_policy: TimeWaitResetPolicy::Maintained,
            polled: false,
        })
    }
    /// Select a bounded optional ingress policy before the first maintained poll.
    /// Existing constructors preserve maintained behavior unless explicitly changed.
    pub fn set_time_wait_reset_policy(&mut self, policy: TimeWaitResetPolicy) -> Result<(), Error> {
        if self.polled {
            return Err(Error::InvalidConfig);
        }
        self.time_wait_reset_policy = policy;
        Ok(())
    }
    /// Admit one validated complete incoming IP/TCP packet, without reading time.
    pub fn ingest(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.config.validate_packet(packet)?;
        if self.queues.incoming.len() >= self.config.packet_slots {
            return Err(Error::QueueFull);
        }
        self.queues.incoming.push_back(packet.to_vec());
        Ok(())
    }
    /// Perform at most `work_limit` single-ingress and bounded-egress iterations.
    pub fn poll(&mut self, now: Millis, work_limit: usize) -> Result<(), Error> {
        if !(1..=1024).contains(&work_limit) {
            return Err(Error::WorkLimit);
        }
        if now < self.last_time {
            return Err(Error::Time);
        }
        let instant = time(now)?;
        self.last_time = now;
        self.polled = true;
        self.interface.poll_maintenance(instant);
        for _ in 0..work_limit {
            let before = self.endpoint().state();
            // Admission validated a fixed 20/40-byte IP header and complete TCP
            // header. Only use flags if the maintained state actually changes.
            let flags = self
                .queues
                .incoming
                .front()
                .and_then(|packet| packet.get(if self.config.local.is_ipv4() { 33 } else { 53 }))
                .copied()
                .unwrap_or(0);
            // Check current maintained state for EACH ingress item: a preceding
            // FIN in this same bounded poll may have just entered TIME-WAIT.
            // Dropping consumes this work step, preserves the maintained timer,
            // and never manufactures a Clean close or acknowledges any bytes.
            if self.time_wait_reset_policy == TimeWaitResetPolicy::IgnoreInTimeWait
                && before == State::TimeWait
                && flags & 4 != 0
            {
                self.queues.incoming.pop_front();
            } else {
                self.interface
                    .poll_ingress_single(instant, &mut self.queues, &mut self.sockets);
                self.observe_transition(before, Some(flags), 0);
            }
            let before = self.endpoint().state();
            let unread = self.endpoint().recv_queue();
            self.interface
                .poll_egress(instant, &mut self.queues, &mut self.sockets);
            self.observe_transition(before, None, unread);
        }
        Ok(())
    }
    /// Transfer ownership of one packet; retain exact bytes until native send succeeds.
    pub fn pop_packet(&mut self) -> Option<Vec<u8>> {
        self.queues.outgoing.pop_front()
    }
    /// Queue original stream bytes; partial/zero progress leaves the remainder with caller.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        self.endpoint_mut()
            .send_slice(bytes)
            .map_err(|_| Error::NotConnected)
    }
    /// Consume only delivered ordered bytes, distinguishing pending work from EOF.
    pub fn read(&mut self, output: &mut [u8]) -> Result<ReadOutcome, Error> {
        if output.is_empty() {
            return Err(Error::EmptyBuffer);
        }
        if self.endpoint().can_recv() {
            return self
                .endpoint_mut()
                .recv_slice(output)
                .map(ReadOutcome::Data)
                .map_err(|_| Error::Stack);
        }
        if let Some(reason) = self
            .close_reason
            .filter(|reason| *reason != CloseReason::Clean)
        {
            return Err(Error::Terminated(reason));
        }
        if !self.endpoint().may_recv() && self.peer_fin {
            Ok(ReadOutcome::Eof)
        } else {
            Ok(ReadOutcome::Pending)
        }
    }
    /// Request FIN after queued stream bytes; continue polling until actual completion.
    pub fn close(&mut self) {
        let before = self.endpoint().state();
        self.endpoint_mut().close();
        if before != State::Closed && self.endpoint().state() == State::Closed {
            self.close_reason = Some(CloseReason::LocalAbort);
        }
    }
    /// Abort locally and let subsequent polling emit the maintained stack's reset.
    pub fn abort(&mut self) {
        self.endpoint_mut().abort();
        self.close_reason.get_or_insert(CloseReason::LocalAbort);
    }
    /// Inspect bounded actual retention without changing protocol state.
    pub fn status(&self) -> Status {
        Status {
            state: self.endpoint().state(),
            established: self.ever_connected,
            peer_fin: self.peer_fin,
            close_reason: self.close_reason,
            incoming_packets: self.queues.incoming.len(),
            outgoing_packets: self.queues.outgoing.len(),
            send_bytes: self.endpoint().send_queue(),
            receive_bytes: self.endpoint().recv_queue(),
            peer_receive_window_bytes: self.endpoint().peer_receive_window(),
        }
    }
    fn endpoint(&self) -> &tcp::Socket<'static> {
        self.sockets.get(self.socket)
    }
    fn endpoint_mut(&mut self) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.socket)
    }

    fn observe_transition(&mut self, before: State, ingress_flags: Option<u8>, unread: usize) {
        let after = self.endpoint().state();
        self.ever_connected |= matches!(
            after,
            State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
                | State::TimeWait
        );
        self.peer_fin |= matches!(after, State::CloseWait | State::Closing | State::TimeWait);
        if before != State::TimeWait && after == State::TimeWait {
            // The public maintained TimeWait timer remains authoritative. The
            // active-peer idle/keepalive policy must not masquerade as that timer.
            self.endpoint_mut().set_timeout(None);
            self.endpoint_mut().set_keep_alive(None);
        }
        if before != State::Closed && after == State::Closed && self.close_reason.is_none() {
            self.close_reason = Some(match ingress_flags {
                Some(flags) if flags & 4 != 0 => CloseReason::PeerReset,
                Some(flags) if before == State::LastAck && flags & 16 != 0 && self.peer_fin => {
                    CloseReason::Clean
                }
                None if before == State::TimeWait && self.peer_fin && unread == 0 => {
                    CloseReason::Clean
                }
                None if before == State::TimeWait && self.peer_fin => CloseReason::UndrainedReceive,
                None => CloseReason::Timeout,
                Some(_) => CloseReason::Unexpected,
            });
        }
    }
}

#[cfg(test)]
mod tests;

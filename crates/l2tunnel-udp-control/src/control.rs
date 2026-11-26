use super::*;
use l2tunnel_recovery::{
    BufferSide, EndpointRole, PacketView, RecoveryContext, RecoveryEngine, SelectiveRepeat,
    inspect_packet,
};

const DOMAIN: &[u8] = b"l2tunnel/openvpn-like/control-record/v1\0";
const HEADER: usize = 32;
const TAG: usize = 32;

/// Authenticated control result; only Fresh may confirm the client's return path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    /// A new authenticated outer record was accepted by bounded recovery.
    Fresh,
    /// A duplicate or older-than-window authenticated outer record was ignored.
    Replay,
}

/// Exact admission accounting plus current bounded retention observations.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlStatistics {
    /// Complete datagrams admitted for transmission, including retry and feedback.
    pub transmitted_packets: u64,
    /// Complete configured IP bytes admitted for transmission.
    pub transmitted_ip_bytes: u64,
    /// Fresh authenticated outer packets accepted by recovery.
    pub received_packets: u64,
    /// Authenticated replay packets ignored without recovery mutation.
    pub replay_packets: u64,
    /// Outbound source bytes awaiting peer recovery acknowledgment.
    pub send_bytes: usize,
    /// Inbound retained source bytes, including a partially read source.
    pub receive_bytes: usize,
}

#[derive(Clone, Copy, Default)]
struct Replay {
    highest: Option<u64>,
    bits: u128,
}
impl Replay {
    fn accept(self, number: u64) -> Option<Self> {
        let Some(highest) = self.highest else {
            return Some(Self {
                highest: Some(number),
                bits: 1,
            });
        };
        if number > highest {
            let distance = number - highest;
            return Some(Self {
                highest: Some(number),
                bits: if distance >= 128 {
                    1
                } else {
                    (self.bits << distance) | 1
                },
            });
        }
        let distance = highest - number;
        if distance >= 128 || self.bits & (1_u128 << distance) != 0 {
            return None;
        }
        Some(Self {
            highest: self.highest,
            bits: self.bits | (1_u128 << distance),
        })
    }
}

/// Ordered authenticated bytes for a TLS implementation, with finite bootstrap life.
///
/// This is not TLS or final member authentication. It consumes only a gate-issued
/// ticket and uses independent directional admission-derived control MAC keys.
/// The caller retains every emitted datagram until actual I/O accepts it. All
/// counters charge admission to caller ownership, not a claimed kernel send.
pub struct ControlEngine {
    config: Config,
    session: [u8; 16],
    role: u8,
    send_key: Secret,
    receive_key: Secret,
    expires: Duration,
    bootstrap_expires: Duration,
    promoted: bool,
    last_now: Duration,
    recovery: SelectiveRepeat,
    replay: Replay,
    next_packet: u64,
    interval_end: Duration,
    packets_left: u32,
    bytes_left: usize,
    partial: Vec<u8>,
    partial_start: usize,
    statistics: ControlStatistics,
}

impl ControlEngine {
    /// Consume one path ticket. Resource configuration was bound into its cookie.
    pub fn new(ticket: PathTicket, now: Duration) -> Result<Self, Error> {
        now_check(now, Duration::ZERO, ticket.deadline)?;
        let config = ticket.config;
        let recovery = SelectiveRepeat::new(config.arq, context(ticket.session, ticket.role))?;
        Ok(Self {
            config,
            session: ticket.session,
            role: ticket.role,
            send_key: ticket.send_key,
            receive_key: ticket.receive_key,
            expires: ticket.deadline,
            bootstrap_expires: ticket.deadline,
            promoted: false,
            last_now: now,
            recovery,
            replay: Replay::default(),
            next_packet: 0,
            interval_end: add(now, config.interval)?,
            packets_left: config.control_packets,
            bytes_left: config.control_bytes,
            partial: Vec::new(),
            partial_start: 0,
            statistics: ControlStatistics::default(),
        })
    }

    /// One-shot trusted-owner promotion after actual verified TLS/member success.
    ///
    /// This pure transport does NOT verify membership. The embedding runtime must
    /// require its actual authenticated TLS capability, exact profile and config
    /// binding before calling. A public session ID, outer MAC or caller boolean
    /// is not membership proof. The positive lease is at most 24 hours and starts
    /// at `now`, which must still precede the original bootstrap expiry. Only the
    /// absolute expiry and time watermark change: keys, packet/replay counters,
    /// ARQ identities/attempts/bytes and emission budgets remain continuous.
    /// No subsequent renewal or in-place rekey is supported.
    pub fn promote_authenticated(&mut self, lease: Duration, now: Duration) -> Result<(), Error> {
        if self.promoted {
            return Err(Error::AlreadyPromoted);
        }
        now_check(now, self.last_now, self.bootstrap_expires)?;
        if lease.is_zero() || lease > Duration::from_secs(24 * 60 * 60) {
            return Err(Error::Configuration);
        }
        let expires = add(now, lease)?;
        self.expires = expires;
        self.promoted = true;
        self.last_now = now;
        Ok(())
    }

    /// Original immutable gate deadline, including after trusted promotion.
    pub fn bootstrap_deadline(&self) -> Duration {
        self.bootstrap_expires
    }

    /// Current absolute lifetime ceiling; incoming traffic never extends it.
    pub fn absolute_deadline(&self) -> Duration {
        self.expires
    }

    /// Admit at most one bounded source from this byte prefix. Zero means retained
    /// send capacity is full (or the input is empty); ownership remains with caller.
    pub fn write(&mut self, bytes: &[u8], now: Duration) -> Result<usize, Error> {
        self.check(now)?;
        let length = bytes.len().min(self.config.arq.max_source_bytes);
        if length == 0 {
            return Ok(0);
        }
        match self.recovery.submit(&bytes[..length], now) {
            Ok(_) => Ok(length),
            Err(RecoveryError::Capacity(BufferSide::Send) | RecoveryError::SequenceWindow) => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    /// Authenticate the complete fixed-peer envelope before any recovery mutation.
    /// Failed input never commits an outer replay number. Retries use fresh outer
    /// numbers but retain the inner source identity and bytes.
    pub fn receive(
        &mut self,
        peer: SocketAddr,
        bytes: &[u8],
        now: Duration,
    ) -> Result<ReceiveOutcome, Error> {
        now_check(now, self.last_now, self.expires)?;
        let peer_ok = if self.role == 0 {
            peer == self.config.path.server
        } else if self.config.path.is_dynamic_client() {
            peer.is_ipv4() == self.config.path.server.is_ipv4()
                && peer.port() != 0
                && !peer.ip().is_unspecified()
                && !peer.ip().is_multicast()
        } else {
            peer == self.config.path.client
        };
        if !peer_ok
            || bytes.len() < CONTROL_OVERHEAD
            || bytes.len() > self.config.max_datagram()
            || !matches!(bytes[0], 32 | 40)
            || bytes[1] != 1
            || bytes[2] != 1 - self.role
            || bytes[3] != 0
            || bytes[4..20] != self.session
            || bytes[30..32] != [0; 2]
        {
            return Err(Error::Malformed);
        }
        let length = usize::from(u16::from_be_bytes([bytes[28], bytes[29]]));
        if length + CONTROL_OVERHEAD != bytes.len() {
            return Err(Error::Malformed);
        }
        let tag_at = HEADER + length;
        if !verify_mac(
            &self.receive_key,
            DOMAIN,
            &bytes[..tag_at],
            self.config.path,
            &bytes[tag_at..],
        ) {
            return Err(Error::Authentication);
        }
        let number = u64::from_be_bytes(bytes[20..28].try_into().map_err(|_| Error::Malformed)?);
        let Some(replay) = self.replay.accept(number) else {
            self.statistics.replay_packets = self
                .statistics
                .replay_packets
                .checked_add(1)
                .ok_or(Error::CounterExhausted)?;
            self.last_now = now;
            return Ok(ReceiveOutcome::Replay);
        };
        let packet = &bytes[HEADER..tag_at];
        let view = inspect_packet(
            packet,
            context(self.session, self.role),
            self.config.arq.max_source_bytes,
        )?;
        if !matches!(
            (bytes[0], view),
            (32, PacketView::Data { .. }) | (40, PacketView::Ack { .. })
        ) {
            return Err(Error::Malformed);
        }
        let received = self
            .statistics
            .received_packets
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        self.recovery.receive(packet, now)?;
        self.replay = replay;
        self.statistics.received_packets = received;
        self.last_now = now;
        Ok(ReceiveOutcome::Fresh)
    }

    /// Emit one due packet under a shared byte/packet budget. One ACK-sized byte
    /// allowance and one packet slot remain reserved from source admission in each
    /// interval. Output must hold the configured complete UDP payload ceiling;
    /// undersized output never burns a source attempt or packet number.
    pub fn poll(&mut self, now: Duration, output: &mut [u8]) -> Result<Option<usize>, Error> {
        now_check(now, self.last_now, self.expires)?;
        if output.len() < self.config.max_datagram() {
            return Err(Error::OutputTooSmall);
        }
        self.check(now)?;
        if now >= self.interval_end {
            self.interval_end = add(now, self.config.interval)?;
            self.packets_left = self.config.control_packets;
            self.bytes_left = self.config.control_bytes;
        }
        if self.packets_left == 0 || self.bytes_left < self.config.ack_charge() {
            return Ok(None);
        }
        let next = self
            .next_packet
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let packet_count = self
            .statistics
            .transmitted_packets
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        self.statistics
            .transmitted_ip_bytes
            .checked_add(self.config.path_mtu as u64)
            .ok_or(Error::CounterExhausted)?;
        let end = self.config.max_datagram() - TAG;
        let (opcode, length) =
            if let Some(length) = self.recovery.poll_feedback(now, &mut output[HEADER..end])? {
                (40, length)
            } else {
                if self.packets_left <= 1
                    || self.bytes_left < self.config.path_mtu + self.config.ack_charge()
                {
                    return Ok(None);
                }
                let Some(length) = self.recovery.poll_source(now, &mut output[HEADER..end])? else {
                    return Ok(None);
                };
                (32, length)
            };
        // Configuration bounded the recovery packet to u16 and this complete IP cost.
        let length_wire = u16::try_from(length).map_err(|_| Error::Configuration)?;
        output[..4].copy_from_slice(&[opcode, 1, self.role, 0]);
        output[4..20].copy_from_slice(&self.session);
        output[20..28].copy_from_slice(&self.next_packet.to_be_bytes());
        output[28..30].copy_from_slice(&length_wire.to_be_bytes());
        output[30..32].fill(0);
        let tag_at = HEADER + length;
        let tag = mac(&self.send_key, DOMAIN, &output[..tag_at], self.config.path);
        output[tag_at..tag_at + TAG].copy_from_slice(&tag);
        let total = length + CONTROL_OVERHEAD;
        let cost = total + self.config.outer_overhead;
        self.next_packet = next;
        self.packets_left -= 1;
        self.bytes_left -= cost;
        self.statistics.transmitted_packets = packet_count;
        self.statistics.transmitted_ip_bytes += cost as u64;
        Ok(Some(total))
    }

    /// Copy ordered bytes, retaining a partially consumed source. In addition to
    /// the ARQ receive limit, at most one max_source_bytes buffer is retained here.
    /// No empty result is an EOF claim; it only means no contiguous bytes are ready.
    pub fn read(&mut self, output: &mut [u8], now: Duration) -> Result<usize, Error> {
        self.check(now)?;
        if output.is_empty() {
            return Ok(0);
        }
        if self.partial_start == self.partial.len() {
            self.partial.resize(self.config.arq.max_source_bytes, 0);
            self.partial_start = 0;
            let Some((_, length)) = self.recovery.poll_delivered(&mut self.partial)? else {
                self.partial.clear();
                return Ok(0);
            };
            self.partial.truncate(length);
        }
        let count = output.len().min(self.partial.len() - self.partial_start);
        output[..count]
            .copy_from_slice(&self.partial[self.partial_start..self.partial_start + count]);
        self.partial_start += count;
        if self.partial_start == self.partial.len() {
            self.partial.clear();
            self.partial_start = 0;
        }
        Ok(count)
    }

    /// Earliest control timer or immutable bootstrap expiry. A caller may also
    /// poll on newly received input or newly admitted bytes.
    pub fn deadline(&self) -> Duration {
        let recovery = self.recovery.deadline().unwrap_or(self.expires);
        let ready = if self.packets_left <= 1
            || self.bytes_left < self.config.path_mtu + self.config.ack_charge()
        {
            recovery.max(self.interval_end)
        } else {
            recovery
        };
        ready.min(self.expires)
    }
    /// Local byte ownership and peer recovery receipt are fully drained.
    pub fn drained(&self) -> bool {
        self.recovery.drained() && self.partial.is_empty()
    }
    /// Public bootstrap session identity; never a secret exporter.
    pub fn session(&self) -> [u8; 16] {
        self.session
    }
    /// Configured maximum caller datagram buffer requirement.
    pub fn max_datagram_bytes(&self) -> usize {
        self.config.max_datagram()
    }
    /// Exact emitted accounting and current retained bytes.
    pub fn statistics(&self) -> ControlStatistics {
        let retained = self.recovery.retained();
        ControlStatistics {
            send_bytes: retained.send_bytes,
            receive_bytes: retained.receive_bytes + self.partial.len() - self.partial_start,
            ..self.statistics
        }
    }
    fn check(&mut self, now: Duration) -> Result<(), Error> {
        now_check(now, self.last_now, self.expires)?;
        self.last_now = now;
        Ok(())
    }
}

fn context(session: [u8; 16], role: u8) -> RecoveryContext {
    RecoveryContext {
        session: u128::from_be_bytes(session),
        epoch: 1,
        role: if role == 0 {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        },
    }
}

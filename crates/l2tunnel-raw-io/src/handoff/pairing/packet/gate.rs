//! One original physical reader, from birth through the terminal packet phase.
use super::*;
use l2tunnel_raw_tcp::packet;
#[path = "compact_gate.rs"]
mod compact;

pub(super) struct Budget {
    policy: PacketPolicy,
    time: Instant,
    byte_tokens: u64,
    packet_tokens: u64,
    byte_remainder: u128,
    packet_remainder: u128,
    pub quota: usize,
}
pub(super) type SharedBudget = Arc<Mutex<Budget>>;
impl Budget {
    pub fn new(policy: PacketPolicy, now: Instant) -> Self {
        Self {
            policy,
            time: now,
            byte_tokens: u64::from(policy.burst_bytes),
            packet_tokens: u64::from(policy.burst_packets),
            byte_remainder: 0,
            packet_remainder: 0,
            quota: 32,
        }
    }
    fn take(&mut self, units: usize) -> bool {
        if self.quota < units {
            return false;
        }
        self.quota -= units;
        true
    }
    fn reserve(&mut self, bytes: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.time).as_nanos();
        self.time = now;
        let byte = elapsed
            .saturating_mul(u128::from(self.policy.bytes_per_second))
            .saturating_add(self.byte_remainder);
        let packets = elapsed
            .saturating_mul(u128::from(self.policy.packets_per_second))
            .saturating_add(self.packet_remainder);
        self.byte_tokens = (u128::from(self.byte_tokens) + byte / 1_000_000_000)
            .min(u128::from(self.policy.burst_bytes)) as u64;
        self.packet_tokens = (u128::from(self.packet_tokens) + packets / 1_000_000_000)
            .min(u128::from(self.policy.burst_packets)) as u64;
        self.byte_remainder = byte % 1_000_000_000;
        self.packet_remainder = packets % 1_000_000_000;
        if self.byte_tokens < bytes as u64 || self.packet_tokens == 0 {
            return false;
        }
        self.byte_tokens -= bytes as u64;
        self.packet_tokens -= 1;
        true
    }
}
#[derive(Clone)]
pub(super) struct Cell {
    pub received_at: Instant,
    pub header: wire::Header,
    pub body: Vec<u8>,
    pub final_metadata: Option<super::compact::FinalMetadata>,
}
pub(super) struct Fence {
    pub local: u32,
    pub peer: u32,
    pub receive_prefix: u64,
    pub local_horizon: u64,
    pub peer_horizon: u64,
    pub peer_scale: u8,
    pub window: u16,
    pub sent: u64,
    pub allocated: u64,
    pub retired: u64,
    pub peer_retired: u64,
}
struct Early {
    cell: Cell,
    sequence: u32,
    ack: u32,
    window: u16,
    wire_len: u64,
}
#[derive(Clone, Copy)]
struct Ranges {
    values: [(u64, u64); 128],
    len: usize,
}
impl Ranges {
    fn new() -> Self {
        Self {
            values: [(0, 0); 128],
            len: 0,
        }
    }
    fn propose(self, start: u64, end: u64, retired: u64, horizon: u64) -> Result<Self, Error> {
        let left = retired.saturating_sub(horizon);
        if start < left || start >= end {
            return Err(Error::Proof);
        }
        let mut out = Self::new();
        let mut merged = (start, end);
        for &(a, b) in &self.values[..self.len] {
            if b <= left {
                continue;
            }
            if a < end && start < b {
                return Err(Error::Proof);
            }
            if b == merged.0 {
                merged.0 = a;
            } else if a == merged.1 {
                merged.1 = b;
            } else {
                if out.len == 128 {
                    return Err(Error::Capacity);
                }
                out.values[out.len] = (a, b);
                out.len += 1;
            }
        }
        // A formerly separate adjacent range can become mergeable after another
        // interval extends either end. Keep the fixed union bounded and exact.
        let mut i = 0;
        while i < out.len {
            let (a, b) = out.values[i];
            if b == merged.0 || a == merged.1 {
                merged = (merged.0.min(a), merged.1.max(b));
                out.len -= 1;
                out.values[i] = out.values[out.len];
                i = 0;
            } else {
                i += 1;
            }
        }
        if out.len == 128 {
            return Err(Error::Capacity);
        }
        out.values[out.len] = merged;
        out.len += 1;
        Ok(out)
    }
}
pub(super) struct GateState {
    pub config: Config,
    pub policy: PacketPolicy,
    pub installed: bool,
    pub transaction: [u8; 16],
    pub opener: Option<PacketOpener>,
    pub final_context: Option<[u8; 32]>,
    pub bootstrap_filter: Option<super::compact::BootstrapFilter>,
    pub fence: Option<Fence>,
    early: Option<Early>,
    pub hello_allowed: bool,
    pub expected_pair: [u8; 32],
    pub session: [u8; 16],
    pub expected_armed: [u8; 32],
    pub incoming: VecDeque<Cell>,
    pub old_reply: Option<Vec<u8>>,
    pub last_old: Option<Instant>,
    pub deadline: Instant,
    pub fault: Option<Error>,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub sent_packets: u64,
    pub rejected_packets: u64,
    pub active: bool,
    pub records_outstanding: usize,
    pub half: bool,
    pub lane: usize,
    pub client: bool,
    pub last_wire: Option<(u32, u32, u16)>,
    pub local_proof: Option<wire::LaneProof>,
    pub peer_hello: Option<[u8; wire::HELLO]>,
    pub commit_body: Option<[u8; wire::COMMIT]>,
    pub ack_body: Option<[u8; wire::COMMIT]>,
    ranges: Ranges,
}
impl GateState {
    pub(super) fn earliest_authenticated_upper_at(&self) -> Option<Instant> {
        self.incoming
            .iter()
            .filter(|cell| {
                cell.final_metadata.is_none()
                    && matches!(cell.header.kind, wire::Kind::Data | wire::Kind::Feedback)
            })
            .map(|cell| cell.received_at)
            .chain(
                self.early
                    .as_ref()
                    .filter(|early| {
                        matches!(
                            early.cell.header.kind,
                            wire::Kind::Data | wire::Kind::Feedback
                        )
                    })
                    .map(|early| early.cell.received_at),
            )
            .min()
    }
    fn new(config: Config, policy: PacketPolicy, deadline: Instant) -> Self {
        Self {
            config,
            policy,
            installed: false,
            transaction: [0; 16],
            opener: None,
            final_context: None,
            bootstrap_filter: None,
            fence: None,
            early: None,
            hello_allowed: false,
            expected_pair: [0; 32],
            session: [0; 16],
            expected_armed: [0; 32],
            incoming: VecDeque::with_capacity(usize::from(policy.queue_packets) + 5),
            old_reply: None,
            last_old: None,
            deadline,
            fault: None,
            received_packets: 0,
            received_bytes: 0,
            sent_bytes: 0,
            sent_packets: 0,
            rejected_packets: 0,
            active: false,
            records_outstanding: 0,
            half: false,
            lane: 0,
            client: false,
            last_wire: None,
            local_proof: None,
            peer_hello: None,
            commit_body: None,
            ack_body: None,
            ranges: Ranges::new(),
        }
    }
    fn reject(&mut self) -> Result<(), Error> {
        self.rejected_packets = self
            .rejected_packets
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        Ok(())
    }
    pub fn ingest_phase(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.fence.is_none() {
            return self.quarantine(bytes);
        }
        let f = self.fence.as_ref().ok_or(Error::Proof)?;
        let p = packet::inspect(self.config, bytes).map_err(|_| Error::Format)?;
        if !p.phase_shape() {
            return Err(Error::Format);
        }
        let mut output = vec![0; usize::from(self.policy.mtu)];
        let tx = self.transaction;
        let policy = self.policy;
        let queued_data = self.records_outstanding
            + self
                .incoming
                .iter()
                .filter(|cell| {
                    cell.final_metadata.is_some_and(|meta| {
                        meta.kind() != super::compact::FinalKind::CarrierControl
                    })
                })
                .count();
        let queued_control = self
            .incoming
            .iter()
            .filter(|c| c.header.kind.control())
            .count();
        let active = self.active;
        let wrong_data_direction = self.half && (self.lane == 0) == self.client;
        let local_proof = self.local_proof;
        let expected_peer = self.peer_hello;
        let pair = self.expected_pair;
        let armed = self.expected_armed;
        let commit_body = self.commit_body;
        let ack_body = self.ack_body;
        let client = self.client;
        let final_selected = self.final_context.is_some();
        let bootstrap_filter = self.bootstrap_filter.clone();
        let bootstrap_live = Instant::now() < self.deadline;
        let count = if self.half { 2 } else { 1 };
        let lane = self.lane;
        let mut protocol_fault = false;
        let ranges = self.ranges;
        let mut range_proposal = None;
        let result = self.opener.as_mut().ok_or(Error::Proof)?.open_checked(
            p.payload,
            &mut output,
            |_, plain| {
                let h = wire::Header::parse(plain)?;
                let end = h
                    .offset
                    .checked_add(p.payload.len() as u64)
                    .ok_or(Error::Exhausted)?;
                if h.transaction != tx
                    || end >= u64::from(u32::MAX - f.peer)
                    || end > f.retired.saturating_add(f.local_horizon)
                    || end.saturating_add(f.local_horizon) < f.retired
                    || h.retired > f.sent
                    || h.right_edge
                        != h.retired
                            .checked_add(f.peer_horizon)
                            .ok_or(Error::Exhausted)?
                    || p.sequence
                        != f.peer
                            .checked_add(u32::try_from(h.offset).map_err(|_| Error::Exhausted)?)
                            .ok_or(Error::Exhausted)?
                    || p.acknowledgment
                        != f.local
                            .checked_add(u32::try_from(h.retired).map_err(|_| Error::Exhausted)?)
                            .ok_or(Error::Exhausted)?
                    || p.window
                        != u16::try_from(f.peer_horizon >> f.peer_scale)
                            .map_err(|_| Error::Proof)?
                {
                    return Err(Error::Proof);
                }
                range_proposal =
                    Some(ranges.propose(h.offset, end, f.retired.max(end), f.local_horizon)?);
                let body = &plain[wire::HEADER..];
                if final_selected
                    && (!bootstrap_live
                        || match h.kind {
                            wire::Kind::Data | wire::Kind::Feedback => {
                                bootstrap_filter.as_ref().is_none_or(|allow| {
                                    !allow(super::compact::BootstrapDirection::Incoming, body)
                                })
                            }
                            wire::Kind::Hello
                            | wire::Kind::Commit
                            | wire::Kind::CommitAck
                            | wire::Kind::Window
                            | wire::Kind::Ping
                            | wire::Kind::Pong => false,
                        })
                {
                    return Err(Error::Proof);
                }
                match h.kind {
                    wire::Kind::Hello => {
                        let hello = wire::Hello::parse(body)?;
                        if hello.count != count
                            || hello.pair != pair
                            || hello.armed != armed
                            || local_proof
                                .ok_or(Error::Proof)?
                                .complementary(hello.lanes[lane].ok_or(Error::Proof)?)
                                .is_err()
                            || expected_peer.is_some_and(|expected| body != expected)
                        {
                            protocol_fault = true;
                            return Err(Error::Proof);
                        }
                    }
                    wire::Kind::Commit => {
                        if client {
                            protocol_fault = true;
                            return Err(Error::Proof);
                        }
                        let expected = commit_body.ok_or(Error::Busy)?;
                        if body != expected {
                            protocol_fault = true;
                            return Err(Error::Proof);
                        }
                    }
                    wire::Kind::CommitAck => {
                        if !client {
                            protocol_fault = true;
                            return Err(Error::Proof);
                        }
                        let expected = ack_body.ok_or(Error::Busy)?;
                        if body != expected {
                            protocol_fault = true;
                            return Err(Error::Proof);
                        }
                    }
                    wire::Kind::Data | wire::Kind::Feedback => {
                        if end
                            > f.retired
                                .checked_add(f.local_horizon)
                                .ok_or(Error::Exhausted)?
                                .saturating_sub(
                                    h.kind.reserved_cells() * (u64::from(policy.mtu) - 40),
                                )
                        {
                            return Err(Error::Capacity);
                        }
                    }
                    _ => {}
                }
                if h.kind == wire::Kind::Data && wrong_data_direction {
                    return Err(Error::Proof);
                }
                if h.kind.control() {
                    if queued_control >= 4 {
                        return Err(Error::Capacity);
                    }
                } else if queued_data
                    >= if active {
                        usize::from(policy.queue_packets)
                    } else {
                        1
                    }
                {
                    return Err(Error::Capacity);
                }
                Ok(())
            },
        );
        match result {
            Err(_) if protocol_fault => {
                self.fault = Some(Error::Proof);
                return Err(Error::Proof);
            }
            Ok(opened) => {
                self.ranges = range_proposal.ok_or(Error::Proof)?;
                let h = wire::Header::parse(&output[..opened.payload_len])?;
                let f = self.fence.as_mut().ok_or(Error::Proof)?;
                f.retired = f.retired.max(h.offset + p.payload.len() as u64);
                f.peer_retired = f.peer_retired.max(h.retired);
                if !h.kind.control() {
                    self.records_outstanding += 1;
                }
                self.incoming.push_back(Cell {
                    received_at: Instant::now(),
                    header: h,
                    body: output[wire::HEADER..opened.payload_len].to_vec(),
                    final_metadata: None,
                });
            }
            Err(l2tunnel_datagram::CheckedOpenError::Datagram(_)) => {
                self.reject()?;
            }
            Err(l2tunnel_datagram::CheckedOpenError::Rejected(Error::Capacity)) => {
                self.reject()?;
            }
            Err(l2tunnel_datagram::CheckedOpenError::Rejected(_)) => {
                self.reject()?;
            }
        }
        Ok(())
    }
    fn quarantine(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let p = packet::inspect(self.config, bytes).map_err(|_| Error::Format)?;
        let mut output = vec![0; usize::from(self.policy.mtu)];
        let tx = self.transaction;
        let allowed = self.hello_allowed;
        let expected_pair = self.expected_pair;
        let session = self.session;
        let expected_armed = self.expected_armed;
        let lane = self.lane;
        let client = self.client;
        let count = if self.half { 2 } else { 1 };
        let policy = self.policy;
        let old = self.early.as_ref().map(|e| e.cell.body.as_slice());
        let mut conflict = false;
        let ranges = self.ranges;
        let mut range_proposal = None;
        let result = self.opener.as_mut().ok_or(Error::Proof)?.open_checked(
            p.payload,
            &mut output,
            |_, plain| {
                let h = wire::Header::parse(plain)?;
                if !allowed || h.kind != wire::Kind::Hello {
                    conflict = true;
                    return Err(Error::Proof);
                }
                let hello = wire::Hello::parse(&plain[wire::HEADER..])?;
                let proof = hello.lanes[lane].ok_or(Error::Proof)?;
                if hello.count != count
                    || hello.pair != expected_pair
                    || hello.armed != expected_armed
                    || proof.session != session
                    || proof.role == if client { 1 } else { 2 }
                {
                    conflict = true;
                    return Err(Error::Proof);
                }
                if old.is_some_and(|old| old != &plain[wire::HEADER..]) {
                    conflict = true;
                    return Err(Error::Proof);
                }
                let horizon = super::transaction::horizon(policy, proof.window, proof.scale)?;
                let end = h
                    .offset
                    .checked_add(p.payload.len() as u64)
                    .ok_or(Error::Exhausted)?;
                if h.transaction != tx
                    || h.retired != 0
                    || h.right_edge != horizon
                    || end >= u64::from(u32::MAX - proof.next)
                    || end > horizon
                    || p.sequence
                        != proof
                            .next
                            .checked_add(u32::try_from(h.offset).map_err(|_| Error::Exhausted)?)
                            .ok_or(Error::Exhausted)?
                    || p.acknowledgment != proof.receive
                    || p.window
                        != u16::try_from(horizon >> proof.scale).map_err(|_| Error::Proof)?
                {
                    return Err(Error::Proof);
                }
                range_proposal = Some(ranges.propose(h.offset, end, end, horizon)?);
                Ok(())
            },
        );
        match result {
            Ok(opened) => {
                self.ranges = range_proposal.ok_or(Error::Proof)?;
                let header = wire::Header::parse(&output[..opened.payload_len])?;
                let candidate = Early {
                    cell: Cell {
                        final_metadata: None,
                        received_at: Instant::now(),
                        header,
                        body: output[wire::HEADER..opened.payload_len].to_vec(),
                    },
                    sequence: p.sequence,
                    ack: p.acknowledgment,
                    window: p.window,
                    wire_len: p.payload.len() as u64,
                };
                if self
                    .early
                    .as_ref()
                    .is_none_or(|old| old.cell.header.offset <= header.offset)
                {
                    self.early = Some(candidate);
                }
            }
            Err(_) if conflict => {
                self.fault = Some(Error::Proof);
                return Err(Error::Proof);
            }
            Err(_) => {
                self.reject()?;
            }
        }
        Ok(())
    }
    fn release_early(&mut self) -> Result<(), Error> {
        let Some(early) = self.early.take() else {
            return Ok(());
        };
        let f = self.fence.as_mut().ok_or(Error::Proof)?;
        let h = early.cell.header;
        let end = h
            .offset
            .checked_add(early.wire_len)
            .ok_or(Error::Exhausted)?;
        if early.sequence
            != f.peer
                .checked_add(u32::try_from(h.offset).map_err(|_| Error::Exhausted)?)
                .ok_or(Error::Exhausted)?
            || early.ack != f.local
            || early.window
                != u16::try_from(f.peer_horizon >> f.peer_scale).map_err(|_| Error::Proof)?
            || h.right_edge != f.peer_horizon
            || end > f.local_horizon
            || end >= u64::from(u32::MAX - f.peer)
        {
            return Err(Error::Proof);
        }
        f.retired = f.retired.max(end);
        self.incoming.push_back(early.cell);
        Ok(())
    }
    fn old(&mut self, bytes: &[u8], now: Instant) -> Result<(), Error> {
        if now >= self.deadline
            || self.old_reply.is_some()
            || self
                .last_old
                .is_some_and(|t| now.saturating_duration_since(t) < Duration::from_millis(250))
        {
            return Ok(());
        }
        let Some(f) = self.fence.as_ref() else {
            return Ok(());
        };
        let Ok(p) = packet::inspect(self.config, bytes) else {
            return Ok(());
        };
        if !p.old_data_shape() {
            return Ok(());
        }
        let distance = u64::from(f.peer.wrapping_sub(p.sequence));
        if distance == 0 || distance > f.receive_prefix || p.payload.len() as u64 > distance {
            return Ok(());
        }
        let mut out = vec![0; 40];
        packet::encode(self.config, f.local, f.peer, f.window, &[], &mut out)
            .map_err(|_| Error::Proof)?;
        self.old_reply = Some(out);
        Ok(())
    }
}
/// Private wrapper identity: it cannot be adopted after a maintained SYN.
pub(super) struct GateIo<I: PacketIo> {
    io: I,
    pub state: Arc<Mutex<GateState>>,
    pub budget: SharedBudget,
    pending: Option<([u8; 32], usize)>,
    pub last_send_at: Option<Instant>,
}
impl<I: PacketIo> GateIo<I> {
    pub fn new(
        io: I,
        config: Config,
        policy: PacketPolicy,
        deadline: Instant,
        budget: SharedBudget,
    ) -> Self {
        Self {
            io,
            state: Arc::new(Mutex::new(GateState::new(config, policy, deadline))),
            budget,
            pending: None,
            last_send_at: None,
        }
    }
    pub fn original(self) -> I {
        self.io
    }
    fn observe(&mut self) -> io::Result<()> {
        let mut s = lock(&self.state).map_err(io::Error::other)?;
        if let Some(e) = &s.fault {
            return Err(io::Error::other(e.to_string()));
        }
        if s.opener.is_some() {
            s.installed = true;
        }
        if s.final_context.is_some() && Instant::now() >= s.deadline {
            s.opener = None;
            s.bootstrap_filter = None;
        }
        Ok(())
    }
    pub fn cancel_pending(&mut self) {
        self.pending = None;
    }
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn drain_early(&mut self) -> Result<(), Error> {
        lock(&self.state)?.release_early()
    }
}
impl<I: PacketIo> PacketIo for GateIo<I> {
    fn receive(&mut self, out: &mut [u8]) -> io::Result<Option<usize>> {
        self.observe()?;
        // Reserve the maximum one receive + one authentication combination before
        // entering caller I/O. There is never a hidden receive loop.
        if !lock(&self.budget).map_err(io::Error::other)?.take(2) {
            return Ok(None);
        }
        let received = {
            let state = lock(&self.state).map_err(io::Error::other)?;
            (
                state
                    .received_packets
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other(Error::Exhausted))?,
                state
                    .received_bytes
                    .checked_add(out.len() as u64)
                    .ok_or_else(|| io::Error::other(Error::Exhausted))?,
            )
        };
        let result = self.io.receive(out)?;
        let Some(n) = result else {
            return Ok(None);
        };
        if n > out.len() {
            return Err(io::Error::other("packet adapter exceeded receive buffer"));
        }
        let mut s = lock(&self.state).map_err(io::Error::other)?;
        s.received_packets = received.0;
        s.received_bytes = received.1 - (out.len() - n) as u64;
        let Ok(p) = packet::inspect(s.config, &out[..n]) else {
            s.reject().map_err(io::Error::other)?;
            return Ok(None);
        };
        // The profile forbids ECN from SYN through shutdown; this does not
        // fabricate ECN acceptance state in the maintained owner.
        if p.flags & 0xc0 != 0 {
            s.reject().map_err(io::Error::other)?;
            return Ok(None);
        }
        if s.final_context.is_some() && super::compact::FinalKind::inspect(p.payload).is_some() {
            s.ingest_final(&out[..n]).map_err(io::Error::other)?;
            return Ok(None);
        }
        let candidate = s.opener.is_some()
            && p.phase_shape()
            && l2tunnel_datagram::inspect_structural(
                CoverProfile::OpenVpnLike,
                s.policy.protection,
                usize::from(s.policy.mtu) - 40,
                usize::from(s.policy.mtu) - s.policy.overhead(),
                p.payload,
            )
            .is_ok();
        if candidate {
            s.ingest_phase(&out[..n]).map_err(io::Error::other)?;
            return Ok(None);
        }
        if s.fence.is_some() {
            s.old(&out[..n], Instant::now()).map_err(io::Error::other)?;
            return Ok(None);
        }
        Ok(Some(n))
    }
    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.observe()?;
        if bytes.get(33).is_some_and(|flags| flags & 0xc0 != 0) {
            return Err(io::Error::other("raw profile forbids ECN"));
        }
        let identity = (profile::hash(bytes), bytes.len());
        let mut b = lock(&self.budget).map_err(io::Error::other)?;
        if !b.take(1) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if let Some(old) = self.pending {
            if old != identity {
                return Err(io::Error::other("changed pending packet"));
            }
        } else {
            if !b.reserve(bytes.len(), Instant::now()) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.pending = Some(identity);
        }
        drop(b);
        let sent = {
            let state = lock(&self.state).map_err(io::Error::other)?;
            (
                state
                    .sent_packets
                    .checked_add(1)
                    .ok_or_else(|| io::Error::other(Error::Exhausted))?,
                state
                    .sent_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| io::Error::other(Error::Exhausted))?,
            )
        };
        match self.io.send(bytes) {
            Ok(()) => {
                self.last_send_at = Some(Instant::now());
                self.pending = None;
                let mut state = lock(&self.state).map_err(io::Error::other)?;
                state.sent_packets = sent.0;
                state.sent_bytes = sent.1;
                let config = Config {
                    local: state.config.peer,
                    peer: state.config.local,
                    ..state.config
                };
                let p = packet::inspect(config, bytes).map_err(io::Error::other)?;
                if p.flags & 0x10 != 0 {
                    state.last_wire = Some((
                        p.sequence
                            .wrapping_add(p.payload.len() as u32)
                            .wrapping_add(u32::from(p.flags & 3 != 0)),
                        p.acknowledgment,
                        p.window,
                    ));
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[path = "gate_tests.rs"]
mod tests;

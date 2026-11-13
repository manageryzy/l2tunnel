//! Runtime of the lean `swift` profile.
//!
//! One task owns a readiness-registered native device, one connected UDP
//! socket and the pure [`l2tunnel_swift`] engines of every ordering channel.
//! Native packets are classified by connection into channels so that a loss
//! delays only the connections sharing its channel. Every
//! datagram is `[packet number u64][ChaCha20-Poly1305 ciphertext][tag]`; the
//! packet number is the nonce, the replay identity and the repair coefficient
//! seed. Keys come from the caller, which derives them from the authenticated
//! TLS exporter. Outbound datagrams are paced by a token bucket in IP bytes so
//! the tunnel fills, and does not overrun, a configured path budget.
//!
//! This module performs no authentication, key derivation or device setup.
pub use codec::control::Policy;
use codec::control::{Message, Refusal};
use l2tunnel_device::{PacketDevice, PacketLayer, READ_BUFFER_BYTES};
use l2tunnel_security::{self as security, swift_v2 as protection};
use l2tunnel_swift as codec;
use std::collections::VecDeque;
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// Packet number and authentication tag added to every engine datagram body.
pub const PROTECTION_BYTES: usize = protection::OVERHEAD_BYTES;
const SCALE: u64 = 1_000_000;
/// Datagrams taken from the socket per readiness event.
const RECEIVE_BATCH: usize = 128;
/// Recovered packets written to the device between socket reads.
const DELIVERY_BATCH: usize = 32;

/// Fixed runtime policy. Both peers bind the protocol part into the
/// authenticated session digest before calling [`run`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Shared engine policy of every channel. Its `queue_bytes` bounds the
    /// native bytes queued across all channels together.
    pub codec: codec::Config,
    /// Independent ordering channels, in `1..=64`.
    pub channels: usize,
    /// Native packet layer, which selects the flow classifier and the header
    /// compression profile.
    pub layer: PacketLayer,
    /// Largest native packet; the engine's record bound is one byte more.
    pub max_native: usize,
    /// Outbound budget in IP bytes per second, in `8_000..=1_250_000_000`.
    pub send_bytes_per_second: u64,
    /// IP and UDP header bytes charged per datagram (28 for IPv4, 48 for IPv6).
    pub network_overhead: usize,
    /// Interval of periodic reports; `None` reports only at termination.
    pub report_interval: Option<Duration>,
}

impl Config {
    /// Validate scalar bounds before any state is allocated.
    pub fn validate(self) -> io::Result<()> {
        self.codec.validate().map_err(invalid)?;
        if !(1..=codec::MAX_CHANNELS).contains(&self.channels)
            || self.max_native + codec::header::MAX_EXPANSION != self.codec.max_packet
            || !(8_000..=1_250_000_000).contains(&self.send_bytes_per_second)
            || !(28..=128).contains(&self.network_overhead)
            || self
                .report_interval
                .is_some_and(|value| value < Duration::from_millis(100))
        {
            return Err(invalid(
                "swift runtime channels, packet bound, rate, overhead or report interval",
            ));
        }
        Ok(())
    }
    fn datagram_cost(self, wire: usize) -> u64 {
        (wire + self.network_overhead) as u64
    }
}

/// Directional data keys from the authenticated exporter.
pub struct Keys<'a> {
    /// Key protecting datagrams this endpoint sends.
    pub send: &'a [u8; 32],
    /// Key protecting datagrams this endpoint receives.
    pub receive: &'a [u8; 32],
}

/// Non-secret counters reported to the embedding frontend.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Microseconds since the runtime started.
    pub elapsed_micros: u64,
    /// Sending engine counters.
    pub sender: codec::SenderStats,
    /// Receiving engine counters.
    pub receiver: codec::ReceiverStats,
    /// Protected datagrams handed to the socket.
    pub datagrams_sent: u64,
    /// IP bytes charged for those datagrams.
    pub ip_bytes_sent: u64,
    /// Protected datagrams that passed authentication and replay checks.
    pub datagrams_received: u64,
    /// Datagrams rejected by authentication, replay or length checks.
    pub datagrams_rejected: u64,
    /// Datagrams the socket refused; the engine treats them as path loss.
    pub socket_drops: u64,
    /// Native packets read from the device and accepted for packing.
    pub native_read: u64,
    /// Native packets from the device dropped as oversized.
    pub native_dropped: u64,
    /// Native packets written to the device.
    pub native_written: u64,
    /// Recovered packets the device refused.
    pub native_write_drops: u64,
    /// Native bytes removed by header compression, net of record tags.
    pub header_bytes_saved: u64,
    /// Key generation currently protecting sent datagrams; zero at start.
    pub key_generation: u64,
    /// Committed policy epoch; zero until the first negotiated change.
    pub policy_epoch: u64,
    /// Policy of the committed epoch, absent while the startup policy holds.
    pub policy: Option<Policy>,
}

/// Original total bound for the current profile's policy change, including
/// proposal, drain and both barriers. The retained name preserves the public
/// API; a duplicate message never extends this bound.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Both directions of one endpoint's configuration for a proposed policy,
/// with the canonical digest both peers must derive identically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Resolved {
    /// Policy of this endpoint's sending engines, pacing and packing queue.
    pub send: Config,
    /// Policy of this endpoint's receiving engines: the peer's sending policy.
    pub receive: Config,
    /// Digest of the complete configuration.
    pub digest: [u8; 32],
}

/// Why a locally requested policy change did not report completion. A refusal
/// preserves the current policy; an ended session can have a partial or unknown
/// peer outcome and never implies rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchError {
    /// Another change is in progress.
    Busy,
    /// Only the initiating endpoint of a session proposes changes.
    NotCoordinator,
    /// The peer refused the proposal.
    Rejected,
    /// The policy is invalid for this session.
    Invalid,
    /// The session ended before the change completed; whether the peer
    /// applied it is unknown and irrelevant, since the session is gone.
    Closed,
}

type Reply = oneshot::Sender<Result<u64, SwitchError>>;
/// Submits policy changes to a running session.
#[derive(Clone)]
pub struct Switcher(mpsc::Sender<(Policy, Reply)>);
/// The runtime's end of a [`Switcher`].
pub struct Requests(mpsc::Receiver<(Policy, Reply)>);
/// A request channel holding one waiting change at a time.
pub fn switcher() -> (Switcher, Requests) {
    let (sender, receiver) = mpsc::channel(1);
    (Switcher(sender), Requests(receiver))
}
impl Switcher {
    /// Negotiate `policy` and resolve with the committed epoch once both
    /// directions have switched. Dropping the future does not cancel a
    /// change that was already proposed.
    pub async fn switch(&self, policy: Policy) -> Result<u64, SwitchError> {
        let (reply, outcome) = oneshot::channel();
        self.0
            .try_send((policy, reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SwitchError::Busy,
                mpsc::error::TrySendError::Closed(_) => SwitchError::Closed,
            })?;
        outcome.await.unwrap_or(Err(SwitchError::Closed))
    }
}

/// Derives the complete configuration of a policy, or refuses it.
pub type Resolver = Box<dyn Fn(&Policy) -> io::Result<Resolved> + Send + Sync>;

/// How this endpoint takes part in policy changes.
pub struct Switching {
    /// Whether this endpoint proposes; exactly one peer of a session does.
    pub coordinator: bool,
    /// Local requests, if this frontend exposes any.
    pub requests: Option<Requests>,
    /// Derive the complete configuration of a policy, or refuse it.
    pub resolve: Resolver,
}
impl Switching {
    /// An endpoint that refuses every change.
    pub fn fixed(coordinator: bool) -> Self {
        Self {
            coordinator,
            requests: None,
            resolve: Box::new(|_| Err(io::Error::from(io::ErrorKind::Unsupported))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendPhase {
    /// Proposed, not agreed: still forwarding under the old policy.
    Proposed,
    /// Agreed: admission stopped, waiting for every source to be confirmed.
    Draining,
    /// Barrier sent, waiting for the peer to replace its receiving state.
    Barrier,
    Done,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceivePhase {
    Open,
    /// Peer's barrier received: delivering what is held before replacing.
    Flushing {
        first_number: u64,
    },
    Done,
}
struct Change {
    epoch: u64,
    deadline: u64,
    policy: Policy,
    resolved: Resolved,
    send: SendPhase,
    receive: ReceivePhase,
}

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}
fn protocol(error: codec::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

/// Token bucket in millionths of an IP byte.
struct Pacer {
    rate: u64,
    burst: i64,
    tokens: i64,
    last: u64,
}
impl Pacer {
    fn new(rate: u64, largest: u64, now: u64) -> Self {
        // Four milliseconds of budget absorbs timer granularity; at least two
        // datagrams so a slow link still makes progress.
        let burst = (rate / 250).max(2 * largest).saturating_mul(SCALE);
        let burst = i64::try_from(burst).unwrap_or(i64::MAX);
        Self {
            rate,
            burst,
            tokens: burst,
            last: now,
        }
    }
    fn refill(&mut self, now: u64) {
        let elapsed = now.saturating_sub(self.last);
        self.last = now;
        let added = u128::from(self.rate) * u128::from(elapsed);
        let added = i64::try_from(added).unwrap_or(i64::MAX);
        self.tokens = self.tokens.saturating_add(added).min(self.burst);
    }
    fn ready(&self) -> bool {
        self.tokens >= 0
    }
    fn charge(&mut self, bytes: u64) {
        let cost = i64::try_from(bytes.saturating_mul(SCALE)).unwrap_or(i64::MAX);
        self.tokens = self.tokens.saturating_sub(cost);
    }
    /// Time at which the bucket is non-negative again.
    fn available_at(&self) -> u64 {
        if self.tokens >= 0 {
            self.last
        } else {
            let debt = self.tokens.unsigned_abs();
            self.last.saturating_add(debt.div_ceil(self.rate))
        }
    }
}

/// Agreed Swift v2 packet interval; unchanged by common packet-protection extraction.
pub const KEY_PACKETS: u64 = protection::KEY_PACKETS;

/// Socket-free protocol state of one endpoint, driven by explicit time.
///
/// Each channel is an independent ordered stream with its own engines. The
/// leading byte of a datagram body carries the kind in its low bits and the
/// channel above them; a feedback datagram concatenates one block per channel.
struct Engine {
    /// Policy of the sending engines, pacing and packing queue.
    config: Config,
    /// Policy of the receiving engines.
    receive: Config,
    /// Largest datagram body any policy of this session allowed.
    limit: usize,
    coordinator: bool,
    change: Option<Change>,
    /// Control messages owed to the peer, a handful at most.
    outbox: VecDeque<Message>,
    /// Result of the locally requested change, once known.
    outcome: Option<Result<u64, SwitchError>>,
    /// Peer sources and repairs numbered below this belong to a drained epoch.
    source_floor: u64,
    /// Peer feedback numbered below this describes a drained epoch.
    feedback_floor: u64,
    saved_base: u64,
    senders: Vec<codec::Sender>,
    receivers: Vec<codec::Receiver>,
    compressors: Vec<codec::header::Compressor>,
    decompressors: Vec<codec::header::Decompressor>,
    seal: protection::Sender,
    open: protection::Receiver,
    pacer: Pacer,
    /// Channel served after the last new source, for round-robin fairness.
    turn: usize,
    /// Earliest time of the next feedback datagram.
    feedback_at: u64,
    feedback_turn: usize,
    /// One bit per channel whose receiver may hold complete packets.
    ready: u64,
    body: Vec<u8>,
    block: Vec<u8>,
    wire: Vec<u8>,
    opened: Vec<u8>,
    native: Vec<u8>,
    record: Vec<u8>,
    snapshot: Snapshot,
}

fn tagged(kind: u8, channel: usize) -> u8 {
    kind | ((channel as u8) << 2)
}

impl Engine {
    fn new(config: Config, keys: &Keys<'_>, now: u64) -> io::Result<Self> {
        config.validate()?;
        let largest = config.datagram_cost(config.codec.datagram_bytes + PROTECTION_BYTES);
        let mut senders = Vec::with_capacity(config.channels);
        let mut receivers = Vec::with_capacity(config.channels);
        let ethernet = config.layer == PacketLayer::Ethernet;
        let mut compressors = Vec::with_capacity(config.channels);
        let mut decompressors = Vec::with_capacity(config.channels);
        for _ in 0..config.channels {
            senders.push(codec::Sender::new(config.codec).map_err(invalid)?);
            receivers.push(codec::Receiver::new(config.codec).map_err(invalid)?);
            compressors.push(codec::header::Compressor::new(ethernet));
            decompressors.push(codec::header::Decompressor::new(ethernet));
        }
        Ok(Self {
            config,
            receive: config,
            limit: config.codec.datagram_bytes,
            coordinator: false,
            change: None,
            outbox: VecDeque::new(),
            outcome: None,
            source_floor: 0,
            feedback_floor: 0,
            saved_base: 0,
            senders,
            receivers,
            compressors,
            decompressors,
            seal: protection::Sender::new(keys.send, security::MAX_BODY_BYTES, KEY_PACKETS)
                .map_err(io::Error::other)?,
            open: protection::Receiver::new(keys.receive, security::MAX_BODY_BYTES, KEY_PACKETS)
                .map_err(io::Error::other)?,
            pacer: Pacer::new(config.send_bytes_per_second, largest, now),
            turn: 0,
            feedback_at: 0,
            feedback_turn: 0,
            ready: 0,
            body: Vec::with_capacity(config.codec.datagram_bytes),
            block: Vec::with_capacity(codec::FEEDBACK_HEADER + 2 * codec::MAX_REQUESTS),
            wire: Vec::with_capacity(config.codec.datagram_bytes + PROTECTION_BYTES),
            opened: Vec::with_capacity(config.codec.datagram_bytes + PROTECTION_BYTES),
            native: Vec::with_capacity(config.codec.max_packet),
            record: Vec::with_capacity(config.codec.max_packet),
            snapshot: Snapshot::default(),
        })
    }
    /// The packing queues share one byte budget, like one bottleneck queue.
    fn has_room(&self) -> bool {
        // Nothing is admitted between agreement and this direction's switch.
        if self
            .change
            .as_ref()
            .is_some_and(|change| !matches!(change.send, SendPhase::Proposed | SendPhase::Done))
        {
            return false;
        }
        let queued: usize = self.senders.iter().map(codec::Sender::queued).sum();
        queued + self.config.codec.max_packet + codec::FRAME_PREFIX <= self.config.codec.queue_bytes
    }
    /// Queue one native packet read from the device.
    fn offer(&mut self, now: u64, packet: &[u8]) -> io::Result<()> {
        // Refuse before compressing: a compressed record must be delivered,
        // or the peer's header contexts would no longer match.
        if packet.is_empty() || packet.len() > self.config.max_native || !self.has_room() {
            self.snapshot.native_dropped += 1;
            return Ok(());
        }
        let channel = match self.config.layer {
            PacketLayer::Ethernet => codec::flow::classify_ethernet(packet, self.config.channels),
            PacketLayer::Ip => codec::flow::classify_ip(packet, self.config.channels),
        };
        self.compressors[channel].compress(packet, &mut self.record);
        if !self.senders[channel]
            .push_packet(now, &self.record)
            .map_err(protocol)?
        {
            return Err(io::Error::other(
                "swift packing queue refused an admitted record",
            ));
        }
        self.snapshot.native_read += 1;
        Ok(())
    }
    /// One feedback datagram body with a block for every channel that owes
    /// one, as far as they fit. Returns whether anything was written.
    fn feedback(&mut self, now: u64) -> bool {
        if now < self.feedback_at {
            return false;
        }
        self.body.clear();
        let block = codec::FEEDBACK_HEADER + 2 * codec::MAX_REQUESTS;
        let mut deferred = false;
        for step in 0..self.receive.channels {
            let channel = (self.feedback_turn + step) % self.receive.channels;
            if self.body.len() + block > self.config.codec.datagram_bytes {
                // Continue with this channel in the next datagram.
                deferred = self.receivers[channel].deadline().is_some();
                if deferred {
                    self.feedback_turn = channel;
                    break;
                }
                continue;
            }
            if self.receivers[channel].feedback(now, &mut self.block) {
                self.block[0] = tagged(codec::KIND_FEEDBACK, channel);
                self.body.extend_from_slice(&self.block);
            }
        }
        if !deferred {
            self.feedback_at = now.saturating_add(self.config.codec.feedback_micros);
        }
        !self.body.is_empty()
    }
    /// The next source, repair or retransmission the budget allows.
    fn data(&mut self, now: u64) -> io::Result<bool> {
        if !self.pacer.ready() {
            return Ok(false);
        }
        let channels = self.config.channels;
        // Requested retransmissions unblock delivery, so they go first.
        let urgent = (0..channels)
            .map(|step| (self.turn + step) % channels)
            .find(|channel| self.senders[*channel].urgent());
        let order = urgent
            .into_iter()
            .chain((0..channels).map(|step| (self.turn + step) % channels));
        for channel in order {
            if self.senders[channel]
                .poll(now, self.seal.next_number().0, &mut self.body)
                .map_err(protocol)?
            {
                self.body[0] = tagged(self.body[0], channel);
                if urgent != Some(channel) {
                    self.turn = (channel + 1) % channels;
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// The next protected datagram due at `now`, if any. Feedback is never
    /// held back by pacing but is charged to the same budget.
    fn produce(&mut self, now: u64) -> io::Result<Option<&[u8]>> {
        self.pacer.refill(now);
        if !self.feedback(now) && !self.data(now)? {
            return Ok(None);
        }
        let length = self
            .body
            .len()
            .checked_add(PROTECTION_BYTES)
            .ok_or_else(|| io::Error::other("swift protected packet size overflow"))?;
        self.wire.resize(length, 0);
        let sealed = self
            .seal
            .seal(&self.body, &mut self.wire)
            .map_err(io::Error::other)?;
        self.wire.truncate(sealed.bytes);
        self.snapshot.key_generation = sealed.generation.0;
        let cost = self.config.datagram_cost(self.wire.len());
        self.pacer.charge(cost);
        self.snapshot.datagrams_sent += 1;
        self.snapshot.ip_bytes_sent += cost;
        Ok(Some(&self.wire))
    }
    /// Earliest time [`Engine::produce`] can have something new without input.
    fn wake(&self, now: u64) -> Option<u64> {
        let send = if self.senders.iter().any(|sender| sender.ready(now)) {
            Some(self.pacer.available_at())
        } else {
            self.senders
                .iter()
                .filter_map(codec::Sender::deadline)
                .min()
        };
        let feedback = self
            .receivers
            .iter()
            .any(|receiver| receiver.deadline().is_some())
            .then_some(self.feedback_at);
        let activity = match (send, feedback) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match (activity, self.change.as_ref().map(|change| change.deadline)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    /// Authenticate and apply one received datagram. Unauthenticated input is
    /// counted and ignored; inconsistent authenticated input ends the session.
    fn accept(&mut self, now: u64, datagram: &[u8]) -> io::Result<()> {
        let limit = self.limit + PROTECTION_BYTES;
        if datagram.len() <= PROTECTION_BYTES || datagram.len() > limit {
            self.snapshot.datagrams_rejected += 1;
            return Ok(());
        }
        self.opened.resize(datagram.len(), 0);
        let opened = match self.open.open(datagram, &mut self.opened) {
            Ok(opened) => opened,
            Err(security::Error::Crypto | security::Error::CounterExhausted) => {
                return Err(io::Error::other("swift receiving key failure"));
            }
            Err(_) => {
                self.snapshot.datagrams_rejected += 1;
                return Ok(());
            }
        };
        let number = opened.number.0;
        let body = &mut self.opened[..opened.bytes];
        self.snapshot.datagrams_received += 1;
        let malformed = || protocol(codec::Error::Malformed);
        let lead = *body.first().ok_or_else(malformed)?;
        let channel = usize::from(lead >> 2);
        if lead & codec::KIND_MASK != codec::KIND_FEEDBACK {
            if number < self.source_floor {
                // A late copy from an epoch that was confirmed in full.
                self.snapshot.receiver.duplicates += 1;
                return Ok(());
            }
            if channel >= self.receive.channels {
                return Err(malformed());
            }
            body[0] = lead & codec::KIND_MASK;
            self.ready |= 1 << channel;
            return self.receivers[channel]
                .on_datagram(number, body)
                .map_err(protocol);
        }
        if number < self.feedback_floor {
            return Ok(());
        }
        let mut rest = body;
        while !rest.is_empty() {
            let lead = rest[0];
            let channel = usize::from(lead >> 2);
            let requests =
                usize::from(*rest.get(codec::FEEDBACK_HEADER - 1).ok_or_else(malformed)?);
            let length = codec::FEEDBACK_HEADER + 2 * requests;
            if lead & codec::KIND_MASK != codec::KIND_FEEDBACK
                || channel >= self.config.channels
                || rest.len() < length
            {
                return Err(malformed());
            }
            let (block, tail) = rest.split_at_mut(length);
            block[0] = codec::KIND_FEEDBACK;
            self.senders[channel]
                .on_feedback(now, block)
                .map_err(protocol)?;
            rest = tail;
        }
        Ok(())
    }
    /// Whether [`Engine::pop`] may still return a packet.
    fn deliverable(&self) -> bool {
        self.ready != 0
    }
    /// The next recovered native packet of any channel, if one is complete.
    fn pop(&mut self) -> io::Result<Option<&[u8]>> {
        while self.ready != 0 {
            let channel = self.ready.trailing_zeros() as usize;
            if self.receivers[channel]
                .pop_packet(&mut self.record)
                .map_err(protocol)?
            {
                self.decompressors[channel]
                    .decompress(&self.record, self.config.max_native, &mut self.native)
                    .map_err(protocol)?;
                return Ok(Some(&self.native));
            }
            self.ready &= !(1 << channel);
        }
        Ok(None)
    }
    fn snapshot(&self, now: u64) -> Snapshot {
        let mut snapshot = Snapshot {
            elapsed_micros: now,
            ..self.snapshot
        };
        for sender in &self.senders {
            snapshot.sender.add(&sender.stats());
        }
        for receiver in &self.receivers {
            snapshot.receiver.add(&receiver.stats());
        }
        snapshot.header_bytes_saved = self.saved_base
            + self
                .compressors
                .iter()
                .map(codec::header::Compressor::saved)
                .sum::<u64>();
        snapshot
    }
    /// Start a locally requested change. `resolved` is this endpoint's
    /// derivation of the policy.
    fn request(
        &mut self,
        now: u64,
        policy: Policy,
        resolved: io::Result<Resolved>,
    ) -> Result<(), SwitchError> {
        if !self.coordinator {
            return Err(SwitchError::NotCoordinator);
        }
        if self.change.is_some() || self.outcome.is_some() {
            return Err(SwitchError::Busy);
        }
        let resolved = resolved.map_err(|_| SwitchError::Invalid)?;
        if self.snapshot.policy == Some(policy) {
            // Already in force: a retry of a completed request.
            self.outcome = Some(Ok(self.snapshot.policy_epoch));
            return Ok(());
        }
        let epoch = self
            .snapshot
            .policy_epoch
            .checked_add(1)
            .ok_or(SwitchError::Invalid)?;
        let deadline = now
            .checked_add(DRAIN_TIMEOUT.as_micros() as u64)
            .ok_or(SwitchError::Invalid)?;
        self.change = Some(Change {
            epoch,
            deadline,
            policy,
            resolved,
            send: SendPhase::Proposed,
            receive: ReceivePhase::Open,
        });
        self.outbox.push_back(Message::Propose { epoch, policy });
        Ok(())
    }
    /// Every phase shares the original deadline. Check before a received
    /// message can change state or a progress turn can report completion.
    fn check_change_deadline(&self, now: u64) -> io::Result<()> {
        if self
            .change
            .as_ref()
            .is_some_and(|change| now >= change.deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "swift policy change exceeded its original deadline",
            ));
        }
        Ok(())
    }
    /// Apply one control message from the authenticated stream. A message
    /// that does not fit the current state is a protocol violation.
    fn on_control(
        &mut self,
        now: u64,
        message: Message,
        resolve: &dyn Fn(&Policy) -> io::Result<Resolved>,
    ) -> io::Result<()> {
        self.check_change_deadline(now)?;
        let violation = || io::Error::new(io::ErrorKind::InvalidData, "swift control out of state");
        match message {
            Message::Propose { epoch, policy } => {
                if self.coordinator {
                    return Err(violation());
                }
                let refuse = |reason| Message::Reject { epoch, reason };
                let reply = if let Some(change) = &self.change {
                    if change.epoch == epoch && change.policy == policy {
                        // A repeated proposal gets the same answer.
                        Message::Accept {
                            epoch,
                            digest: change.resolved.digest,
                        }
                    } else {
                        refuse(Refusal::Busy)
                    }
                } else if self.snapshot.policy_epoch.checked_add(1) != Some(epoch) {
                    refuse(Refusal::Epoch)
                } else if let Ok(resolved) = resolve(&policy) {
                    let deadline = now
                        .checked_add(DRAIN_TIMEOUT.as_micros() as u64)
                        .ok_or_else(|| io::Error::other("swift policy deadline exhausted"))?;
                    self.change = Some(Change {
                        epoch,
                        deadline,
                        policy,
                        resolved,
                        send: SendPhase::Draining,
                        receive: ReceivePhase::Open,
                    });
                    Message::Accept {
                        epoch,
                        digest: resolved.digest,
                    }
                } else {
                    refuse(Refusal::Invalid)
                };
                self.outbox.push_back(reply);
            }
            Message::Accept { epoch, digest } => {
                let change = self.change.as_mut().ok_or_else(violation)?;
                if change.epoch != epoch || change.send != SendPhase::Proposed {
                    return Err(violation());
                }
                if change.resolved.digest != digest {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "swift peers derived different configurations",
                    ));
                }
                change.send = SendPhase::Draining;
            }
            Message::Reject { epoch, .. } => {
                let change = self.change.as_ref().ok_or_else(violation)?;
                if change.epoch != epoch || change.send != SendPhase::Proposed {
                    return Err(violation());
                }
                self.change = None;
                self.outcome = Some(Err(SwitchError::Rejected));
            }
            Message::Barrier {
                epoch,
                first_number,
            } => {
                let change = self.change.as_mut().ok_or_else(violation)?;
                if change.epoch != epoch
                    || change.send == SendPhase::Proposed
                    || change.receive != ReceivePhase::Open
                {
                    return Err(violation());
                }
                change.receive = ReceivePhase::Flushing { first_number };
            }
            Message::BarrierAck {
                epoch,
                feedback_from,
            } => {
                let change = self.change.as_mut().ok_or_else(violation)?;
                if change.epoch != epoch || change.send != SendPhase::Barrier {
                    return Err(violation());
                }
                change.send = SendPhase::Done;
                let config = change.resolved.send;
                self.replace_senders(now, config)?;
                self.feedback_floor = feedback_from;
            }
        }
        Ok(())
    }
    fn replace_senders(&mut self, now: u64, config: Config) -> io::Result<()> {
        config.validate()?;
        for sender in &self.senders {
            self.snapshot.sender.add(&sender.stats());
        }
        self.saved_base += self
            .compressors
            .iter()
            .map(codec::header::Compressor::saved)
            .sum::<u64>();
        let ethernet = config.layer == PacketLayer::Ethernet;
        self.senders.clear();
        self.compressors.clear();
        for _ in 0..config.channels {
            self.senders
                .push(codec::Sender::new(config.codec).map_err(invalid)?);
            self.compressors
                .push(codec::header::Compressor::new(ethernet));
        }
        let largest = config.datagram_cost(config.codec.datagram_bytes + PROTECTION_BYTES);
        self.pacer = Pacer::new(config.send_bytes_per_second, largest, now);
        self.limit = self.limit.max(config.codec.datagram_bytes);
        self.turn = 0;
        self.config = config;
        Ok(())
    }
    fn replace_receivers(&mut self, config: Config) -> io::Result<()> {
        config.validate()?;
        for receiver in &self.receivers {
            self.snapshot.receiver.add(&receiver.stats());
        }
        let ethernet = config.layer == PacketLayer::Ethernet;
        self.receivers.clear();
        self.decompressors.clear();
        for _ in 0..config.channels {
            self.receivers
                .push(codec::Receiver::new(config.codec).map_err(invalid)?);
            self.decompressors
                .push(codec::header::Decompressor::new(ethernet));
        }
        self.limit = self.limit.max(config.codec.datagram_bytes);
        self.feedback_turn = 0;
        self.ready = 0;
        self.receive = config;
        Ok(())
    }
    /// Advance a change in progress: send this direction's barrier once it
    /// has drained, replace receiving state once the peer's barrier arrived
    /// and everything held was delivered, and commit when both are done.
    fn progress(&mut self, now: u64) -> io::Result<()> {
        self.check_change_deadline(now)?;
        let Some(change) = self.change.as_mut() else {
            return Ok(());
        };
        if change.send == SendPhase::Draining
            && self
                .senders
                .iter()
                .all(|sender| sender.unconfirmed() == 0 && sender.queued() == 0)
        {
            change.send = SendPhase::Barrier;
            self.outbox.push_back(Message::Barrier {
                epoch: change.epoch,
                first_number: self.seal.next_number().0,
            });
        }
        if let ReceivePhase::Flushing { first_number } = change.receive
            && self.ready == 0
        {
            if self
                .receivers
                .iter()
                .any(|receiver| receiver.pending() != 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "swift barrier before the previous epoch was delivered",
                ));
            }
            change.receive = ReceivePhase::Done;
            let (epoch, config) = (change.epoch, change.resolved.receive);
            self.replace_receivers(config)?;
            self.source_floor = first_number;
            self.outbox.push_back(Message::BarrierAck {
                epoch,
                feedback_from: self.seal.next_number().0,
            });
        }
        if let Some(change) = &self.change
            && change.send == SendPhase::Done
            && change.receive == ReceivePhase::Done
            && self.outbox.is_empty()
        {
            self.snapshot.policy_epoch = change.epoch;
            self.snapshot.policy = Some(change.policy);
            if self.coordinator {
                self.outcome = Some(Ok(change.epoch));
            }
            self.change = None;
        }
        Ok(())
    }
}

/// Datagram socket errors that describe the path or a momentary local
/// condition, not an unusable socket: a full buffer, a peer that is not bound
/// yet, a firewall or connection-tracking drop, or a missing route. The engine
/// recovers from them exactly as from a datagram lost in transit.
fn path_loss(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
    )
}

async fn tick(interval: &mut Option<tokio::time::Interval>) {
    match interval {
        Some(interval) => {
            interval.tick().await;
        }
        None => std::future::pending().await,
    }
}

fn micros(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX)
}

async fn next_request(requests: &mut Option<Requests>) -> Option<(Policy, Reply)> {
    match requests {
        Some(requests) => requests.0.recv().await,
        None => std::future::pending().await,
    }
}

/// Longest a control frame may take to enter the stream's send buffer.
const CONTROL_WRITE: Duration = Duration::from_secs(5);

/// Forward native packets until the peer closes `control` or an error occurs.
///
/// `socket` must already be connected to the single peer. `control` is the
/// retained authenticated stream: it carries only the profile's control
/// messages, and its closure ends the session. `report` receives a snapshot
/// on every configured interval and once at termination.
pub async fn run<D, S>(
    device: D,
    socket: UdpSocket,
    keys: Keys<'_>,
    config: Config,
    control: S,
    switching: Switching,
    mut report: impl FnMut(&Snapshot),
) -> io::Result<()>
where
    D: PacketDevice<Error = io::Error> + AsRawFd,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();
    let mut engine = Engine::new(config, &keys, 0)?;
    engine.coordinator = switching.coordinator;
    let Switching {
        mut requests,
        resolve,
        ..
    } = switching;
    let (mut reader, mut writer) = tokio::io::split(control);
    let mut inbound: Vec<u8> = Vec::with_capacity(2 * codec::control::MAX_FRAME);
    let mut chunk = [0u8; 256];
    let mut frame = Vec::with_capacity(codec::control::MAX_FRAME);
    let mut waiting: Option<Reply> = None;
    let mut device = AsyncFd::with_interest(device, Interest::READABLE)?;
    let mut interval = config.report_interval.map(tokio::time::interval);
    let mut read = vec![0; READ_BUFFER_BYTES];
    let mut datagram = vec![0; 65_536];
    let result = async {
        loop {
        let now = micros(start);
        engine.progress(now)?;
        while let Some(message) = engine.outbox.pop_front() {
            frame.clear();
            message.encode(&mut frame);
            let write_started = micros(start);
            engine.check_change_deadline(write_started)?;
            let write_limit = engine.change.as_ref().map_or(CONTROL_WRITE, |change| {
                CONTROL_WRITE.min(Duration::from_micros(change.deadline - write_started))
            });
            tokio::time::timeout(write_limit, async {
                writer.write_all(&frame).await?;
                writer.flush().await
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "swift control write stalled")
            })??;
        }
        // A terminal BarrierAck may have been queued by the first progress
        // turn. Commit only after that write actually completed and a fresh
        // time sample still satisfies the original transaction deadline.
        let now = micros(start);
        engine.progress(now)?;
        if let Some(outcome) = engine.outcome.take()
            && let Some(reply) = waiting.take()
        {
            // The requester may have stopped waiting; the change stands.
            let _ = reply.send(outcome);
        }
        // Everything the budget allows right now.
        loop {
            let Some(wire) = engine.produce(now)? else {
                break;
            };
            match socket.try_send(wire) {
                Ok(_) => {}
                Err(error) if path_loss(&error) => engine.snapshot.socket_drops += 1,
                Err(error) => return Err(error),
            }
        }
        // A bounded batch of recovered packets, so that a long in-order run
        // released by one retransmission cannot starve the socket.
        for _ in 0..DELIVERY_BATCH {
            let Some(packet) = engine.pop()? else {
                break;
            };
            match device.get_mut().transmit(packet) {
                Ok(()) => engine.snapshot.native_written += 1,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    engine.snapshot.native_write_drops += 1;
                }
                Err(error) => return Err(error),
            }
        }
        let wait = if engine.deliverable() {
            Duration::ZERO
        } else {
            // `wake` includes the original policy-change deadline, even
            // when no datagram or control message arrives.
            let idle = if engine.change.is_some() {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(3600)
            };
            engine.wake(now).map_or(idle, |at| {
                Duration::from_micros(at.saturating_sub(now).max(200)).min(idle)
            })
        };
        let wait = engine.change.as_ref().map_or(wait, |change| {
            wait.min(Duration::from_micros(change.deadline - now))
        });
        tokio::select! {
            biased;
            read = reader.read(&mut chunk) => {
                let length = read?;
                if length == 0 {
                    break Ok(());
                }
                inbound.extend_from_slice(&chunk[..length]);
                let mut used = 0;
                while let Some((message, consumed)) =
                    Message::decode(&inbound[used..]).map_err(protocol)?
                {
                    used += consumed;
                    engine.on_control(micros(start), message, &*resolve)?;
                }
                inbound.drain(..used);
            }
            request = next_request(&mut requests), if waiting.is_none() => {
                match request {
                    Some((policy, reply)) => match engine.request(micros(start), policy, resolve(&policy)) {
                        Ok(()) => waiting = Some(reply),
                        Err(error) => {
                            let _ = reply.send(Err(error));
                        }
                    },
                    None => requests = None,
                }
            }
            result = socket.readable() => {
                result?;
                for _ in 0..RECEIVE_BATCH {
                    match socket.try_recv(&mut datagram) {
                        Ok(length) => engine.accept(micros(start), &datagram[..length])?,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        // A queued ICMP error about an earlier datagram.
                        Err(error) if path_loss(&error) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
            result = async { device.readable().await.map(drop) }, if engine.has_room() => {
                result?;
                for _ in 0..64 {
                    if !engine.has_room() {
                        break;
                    }
                    let received = device.try_io_mut(Interest::READABLE, |device| {
                        device
                            .receive(&mut read)?
                            .ok_or_else(|| io::ErrorKind::WouldBlock.into())
                    });
                    match received {
                        Ok(length) => engine.offer(micros(start), &read[..length])?,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) => return Err(error),
                    }
                }
            }
            _ = tokio::time::sleep(wait) => {}
            _ = tick(&mut interval) => report(&engine.snapshot(micros(start))),
        }
        }
    }
    .await;
    report(&engine.snapshot(micros(start)));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rate: u64, channels: usize) -> Config {
        Config {
            codec: codec::Config {
                datagram_bytes: 1448,
                window: 64,
                repair_numerator: 0,
                repair_denominator: 1000,
                flow_sources: 1024,
                queue_bytes: 64 * 1024,
                max_packet: 1601,
                flush_micros: 0,
                feedback_micros: 5_000,
                tail_micros: 10_000,
                min_rto_micros: 20_000,
                max_rto_micros: 1_000_000,
            },
            channels,
            layer: PacketLayer::Ip,
            max_native: 1600,
            send_bytes_per_second: rate,
            network_overhead: 28,
            report_interval: None,
        }
    }
    fn pair(rate: u64, channels: usize) -> io::Result<(Engine, Engine)> {
        let (a, b) = ([1; 32], [2; 32]);
        let left = Keys {
            send: &a,
            receive: &b,
        };
        let right = Keys {
            send: &b,
            receive: &a,
        };
        Ok((
            Engine::new(config(rate, channels), &left, 0)?,
            Engine::new(config(rate, channels), &right, 0)?,
        ))
    }
    fn test_policy(channels: u8, repair_permille: u16, path_mtu: u16, kbit: u32) -> Policy {
        Policy {
            path_mtu,
            forward_kbit: kbit,
            reverse_kbit: kbit,
            channels,
            window: 32,
            repair_permille,
        }
    }
    /// Both endpoints derive the same configuration and digest from a policy.
    fn resolver(client: bool) -> Resolver {
        Box::new(move |policy| {
            let make = |kbit: u32| {
                let mut value = config(u64::from(kbit) * 125, usize::from(policy.channels));
                value.codec.datagram_bytes = usize::from(policy.path_mtu).saturating_sub(52);
                value.codec.window = usize::from(policy.window);
                value.codec.repair_numerator = u32::from(policy.repair_permille);
                value.codec.flush_micros = 500;
                value.report_interval = Some(Duration::from_millis(100));
                value
            };
            let (send, receive) = if client {
                (make(policy.forward_kbit), make(policy.reverse_kbit))
            } else {
                (make(policy.reverse_kbit), make(policy.forward_kbit))
            };
            send.validate()?;
            receive.validate()?;
            let mut digest = [0; 32];
            digest[..2].copy_from_slice(&policy.path_mtu.to_be_bytes());
            digest[2..6].copy_from_slice(&policy.forward_kbit.to_be_bytes());
            digest[6] = policy.channels;
            digest[7] = policy.window;
            digest[8..10].copy_from_slice(&policy.repair_permille.to_be_bytes());
            Ok(Resolved {
                send,
                receive,
                digest,
            })
        })
    }
    /// A minimal IPv4/TCP packet of one connection carrying a counter.
    fn segment(port: u16, counter: u32, length: usize) -> Vec<u8> {
        let mut packet = vec![0u8; length.max(44)];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..20].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
        packet[20..22].copy_from_slice(&port.to_be_bytes());
        packet[22..24].copy_from_slice(&24_500u16.to_be_bytes());
        packet[40..44].copy_from_slice(&counter.to_be_bytes());
        packet
    }
    fn counter_of(packet: &[u8]) -> u32 {
        counter(packet).1
    }
    fn counter(packet: &[u8]) -> (u16, u32) {
        (
            u16::from_be_bytes([packet[20], packet[21]]),
            u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]),
        )
    }

    #[test]
    fn protected_engines_deliver_in_order_and_reject_tamper_and_replay() -> io::Result<()> {
        let (mut left, mut right) = pair(12_500_000, 1)?;
        let packets: Vec<Vec<u8>> = (0..40u8)
            .map(|i| vec![i; 60 + usize::from(i) * 30])
            .collect();
        for packet in &packets {
            left.offer(0, packet)?;
        }
        let mut wires = Vec::new();
        while let Some(wire) = left.produce(0)? {
            assert!(wire.len() <= 1448 + PROTECTION_BYTES);
            wires.push(wire.to_vec());
        }
        assert!(!wires.is_empty());
        // The body is not visible on the wire.
        assert!(!wires[0].windows(32).any(|window| window == [0u8; 32]));
        let mut tampered = wires[0].clone();
        tampered[20] ^= 1;
        right.accept(1, &tampered)?;
        right.accept(1, &wires[0][..10])?;
        assert_eq!(right.snapshot(1).datagrams_rejected, 2);
        let mut delivered = Vec::new();
        for wire in &wires {
            right.accept(1, wire)?;
            while let Some(packet) = right.pop()? {
                delivered.push(packet.to_vec());
            }
        }
        assert_eq!(delivered, packets);
        let accepted = right.snapshot(1).datagrams_received;
        for wire in &wires {
            right.accept(2, wire)?;
        }
        assert_eq!(
            right.snapshot(2).datagrams_received,
            accepted,
            "replay accepted"
        );
        // A key from the wrong direction authenticates nothing.
        let (mut other, _) = pair(12_500_000, 1)?;
        other.accept(1, &wires[0])?;
        assert_eq!(other.snapshot(1).datagrams_received, 0);
        // Feedback returns and confirms everything.
        let feedback = right.produce(10_000)?.map(<[u8]>::to_vec);
        let feedback = feedback.ok_or_else(|| io::Error::other("no feedback"))?;
        left.accept(10_000, &feedback)?;
        assert_eq!(left.senders[0].unconfirmed(), 0);
        Ok(())
    }

    /// Sixteen connections over sixteen channels with every seventh datagram
    /// lost each way: every connection sees its own packets exactly once and
    /// in order, a gap in one channel does not hold back the others, and one
    /// feedback datagram serves all channels.
    #[test]
    fn channels_order_each_connection_independently_under_loss() -> io::Result<()> {
        let (mut left, mut right) = pair(12_500_000, 16)?;
        let mut next = [0u32; 64];
        let mut expected = [0u32; 64];
        let mut total = 0;
        let mut overtaken = false;
        let mut order = Vec::new();
        let (mut forward, mut backward) = (0u64, 0u64);
        let mut now = 0;
        while total < 16 * 300 {
            now += 1_000;
            assert!(now < 60_000_000, "stalled at {total}");
            for port in 0..16u16 {
                let index = usize::from(port);
                if next[index] < 300 && left.has_room() {
                    left.offer(now, &segment(port, next[index], 1400))?;
                    next[index] += 1;
                }
            }
            let mut wires = Vec::new();
            while let Some(wire) = left.produce(now)? {
                wires.push(wire.to_vec());
            }
            for wire in wires {
                forward += 1;
                if forward % 7 == 3 {
                    continue;
                }
                right.accept(now, &wire)?;
                while let Some(packet) = right.pop()? {
                    let (port, value) = counter(packet);
                    let index = usize::from(port);
                    assert_eq!(value, expected[index], "connection {port} out of order");
                    expected[index] += 1;
                    total += 1;
                    order.push(port);
                }
            }
            let mut wires = Vec::new();
            while let Some(wire) = right.produce(now)? {
                wires.push(wire.to_vec());
            }
            for wire in wires {
                backward += 1;
                if backward % 7 != 5 {
                    left.accept(now, &wire)?;
                }
            }
            // Some connection is ahead of another by more than one round.
            let (low, high) = (expected[..16].iter().min(), expected[..16].iter().max());
            overtaken |= matches!((low, high), (Some(low), Some(high)) if high - low > 2);
        }
        assert!(overtaken, "a gap in one channel held every connection back");
        assert!(expected[..16].iter().all(|count| *count == 300));
        let report = right.snapshot(now);
        assert!(report.receiver.packets == 16 * 300);
        // Far fewer feedback datagrams than per-channel feedback blocks.
        assert!(right.snapshot.datagrams_sent * 4 < report.receiver.feedback);
        let sent = left.snapshot(now).sender;
        assert!(sent.retransmits > 0 && sent.repairs == 0);
        assert!(order.windows(2).any(|pair| pair[0] != pair[1]));
        Ok(())
    }

    /// Keys change at fixed packet numbers with no message. Traffic keeps
    /// flowing across many generations in both directions; stragglers of the
    /// previous generation are still accepted inside the replay window; a
    /// forged claim of the next generation, a skipped generation and a
    /// retired generation authenticate nothing.
    #[test]
    fn keys_ratchet_at_fixed_packet_numbers_without_interrupting_traffic() -> io::Result<()> {
        let (mut left, mut right) = pair(12_500_000, 1)?;
        // The production factory always supplies KEY_PACKETS. These fresh
        // test owners use a short agreed interval to exercise runtime wiring.
        left.seal = protection::Sender::new(&[1; 32], security::MAX_BODY_BYTES, 8)
            .map_err(io::Error::other)?;
        left.open = protection::Receiver::new(&[2; 32], security::MAX_BODY_BYTES, 8)
            .map_err(io::Error::other)?;
        right.seal = protection::Sender::new(&[2; 32], security::MAX_BODY_BYTES, 8)
            .map_err(io::Error::other)?;
        right.open = protection::Receiver::new(&[1; 32], security::MAX_BODY_BYTES, 8)
            .map_err(io::Error::other)?;
        let mut now = 0;
        let mut delivered = 0u32;
        let mut held: Option<Vec<u8>> = None;
        let mut first: Option<Vec<u8>> = None;
        for counter in 0..400u32 {
            now += 2_000;
            left.offer(now, &segment(7, counter, 900))?;
            while let Some(wire) = left.produce(now)? {
                let wire = wire.to_vec();
                let number = u64::from_be_bytes(wire[..8].try_into().map_err(io::Error::other)?);
                first.get_or_insert_with(|| wire.clone());
                // Hold the last datagram of generation 2 back until the
                // receiver has moved to generation 3.
                if number == 23 {
                    held = Some(wire);
                    continue;
                }
                right.accept(now, &wire)?;
                if number == 26
                    && let Some(late) = held.take()
                {
                    let before = right.snapshot(now).datagrams_received;
                    right.accept(now, &late)?;
                    assert_eq!(right.snapshot(now).datagrams_received, before + 1);
                }
            }
            while let Some(packet) = right.pop()? {
                assert_eq!(counter_of(packet), delivered);
                delivered += 1;
            }
            while let Some(wire) = right.produce(now)? {
                let wire = wire.to_vec();
                left.accept(now, &wire)?;
            }
        }
        for _ in 0..200 {
            now += 5_000;
            while let Some(wire) = left.produce(now)? {
                let wire = wire.to_vec();
                right.accept(now, &wire)?;
            }
            while let Some(packet) = right.pop()? {
                assert_eq!(counter_of(packet), delivered);
                delivered += 1;
            }
            while let Some(wire) = right.produce(now)? {
                let wire = wire.to_vec();
                left.accept(now, &wire)?;
            }
        }
        assert_eq!(delivered, 400);
        let sent = left.snapshot(now);
        assert!(sent.key_generation >= 40, "{sent:?}");
        assert_eq!(sent.key_generation, (left.seal.next_number().0 - 1) / 8);
        assert_eq!(right.open.generation().0, sent.key_generation);
        assert!(right.snapshot(now).key_generation >= 1);
        assert_eq!(right.snapshot(now).datagrams_rejected, 0);
        // Old packets remain rejected. Primitive key-retirement and exact
        // replay-boundary tests live with the shared protection implementation.
        let first = first.ok_or_else(|| io::Error::other("nothing sent"))?;
        let current = right.open.generation().0;
        assert_eq!(
            right
                .open
                .previous_generation()
                .map(|generation| generation.0),
            Some(current - 1)
        );
        right.accept(now, &first)?;
        assert_eq!(right.snapshot(now).datagrams_rejected, 1);
        // A forged datagram naming the next generation derives the candidate
        // key once but does not move the receiver; one naming a generation
        // further ahead is refused outright.
        let current = right.open.generation().0;
        for generation in [current + 1, current + 2, current + 9] {
            let mut forged = vec![0u8; 80];
            forged[..8].copy_from_slice(&(generation * 8).to_be_bytes());
            right.accept(now, &forged)?;
        }
        assert_eq!(right.snapshot(now).datagrams_rejected, 4);
        assert_eq!(right.open.generation().0, current);
        Ok(())
    }

    /// One millisecond of both engines: control messages, datagrams (every
    /// `lose`-th dropped when nonzero) and delivery. Returns the counters of
    /// the packets delivered at (right, left).
    fn step(
        left: &mut Engine,
        right: &mut Engine,
        now: &mut u64,
        lose: u64,
        sent: &mut u64,
    ) -> io::Result<(Vec<u32>, Vec<u32>)> {
        *now += 1_000;
        let (client, server) = (resolver(true), resolver(false));
        left.progress(*now)?;
        right.progress(*now)?;
        while let Some(message) = left.outbox.pop_front() {
            right.on_control(*now, message, &*server)?;
        }
        while let Some(message) = right.outbox.pop_front() {
            left.on_control(*now, message, &*client)?;
        }
        let mut delivered = (Vec::new(), Vec::new());
        for forward in [true, false] {
            let (from, to) = if forward {
                (&mut *left, &mut *right)
            } else {
                (&mut *right, &mut *left)
            };
            while let Some(wire) = from.produce(*now)? {
                let wire = wire.to_vec();
                *sent += 1;
                if lose == 0 || !(*sent).is_multiple_of(lose) {
                    to.accept(*now, &wire)?;
                }
            }
            while let Some(packet) = to.pop()? {
                let value = counter_of(packet);
                if forward {
                    delivered.0.push(value);
                } else {
                    delivered.1.push(value);
                }
            }
        }
        Ok(delivered)
    }

    /// A change is agreed, each direction stops admitting, drains under loss,
    /// crosses its barrier and resumes with the new policy; every packet
    /// offered before, during and after arrives exactly once and in order,
    /// and late datagrams of the drained epoch are harmless.
    #[test]
    fn policy_change_drains_each_direction_then_switches_without_losing_order() -> io::Result<()> {
        let (mut left, mut right) = pair(2_500_000, 4)?;
        left.coordinator = true;
        let policy = test_policy(2, 200, 1400, 16_000);
        let (mut now, mut sent) = (0, 0);
        let (mut offered, mut got) = ((0u32, 0u32), (Vec::new(), Vec::new()));
        let mut stale_source = None;
        let mut stale_feedback = None;
        let mut paused = false;
        for tick in 0..4_000u32 {
            for (engine, count) in [(&mut left, &mut offered.0), (&mut right, &mut offered.1)] {
                if *count < 600 && engine.has_room() {
                    engine.offer(now, &segment(9, *count, 700))?;
                    *count += 1;
                }
            }
            if tick == 150 {
                // Keep one datagram of each kind from the first epoch.
                left.offer(now, &segment(9, offered.0, 700))?;
                offered.0 += 1;
                stale_source = left.produce(now + 1)?.map(<[u8]>::to_vec);
                if let Some(wire) = &stale_source {
                    right.accept(now + 1, wire)?;
                }
                stale_feedback = right.produce(now + 10_000)?.map(<[u8]>::to_vec);
                assert_eq!(left.request(now, policy, resolver(true)(&policy)), Ok(()));
                assert_eq!(
                    left.request(now, policy, resolver(true)(&policy)),
                    Err(SwitchError::Busy)
                );
            }
            let delivered = step(&mut left, &mut right, &mut now, 7, &mut sent)?;
            got.0.extend(delivered.0);
            got.1.extend(delivered.1);
            if let Some(change) = &left.change
                && change.send != SendPhase::Proposed
                && change.send != SendPhase::Done
            {
                // Between agreement and the switch nothing is admitted.
                assert!(!left.has_room());
                paused = true;
            }
        }
        assert!(paused, "the sending direction never paused");
        assert_eq!(left.outcome, Some(Ok(1)));
        assert!(left.change.is_none() && right.change.is_none());
        for engine in [&left, &right] {
            let snapshot = engine.snapshot(now);
            assert_eq!(snapshot.policy_epoch, 1);
            assert_eq!(snapshot.policy, Some(policy));
            assert_eq!(engine.config.channels, 2);
            assert_eq!(engine.receive.channels, 2);
            assert_eq!(engine.config.codec.datagram_bytes, 1348);
            assert_eq!(engine.config.send_bytes_per_second, 2_000_000);
            // Counters of the replaced engines are kept.
            assert_eq!(snapshot.native_read, u64::from(offered.0.max(offered.1)));
            assert!(snapshot.sender.sources > 0 && snapshot.receiver.sources > 0);
        }
        assert_eq!(offered, (600, 600));
        assert_eq!(got.0, (0..600).collect::<Vec<u32>>());
        assert_eq!(got.1, (0..600).collect::<Vec<u32>>());
        // Datagrams of the drained epoch arriving late are counted and
        // ignored; they cannot disturb the new engines. The replay window
        // has moved on, so present them to engines that never saw them.
        let stale_source = stale_source.ok_or_else(|| io::Error::other("no stale source"))?;
        let stale_feedback = stale_feedback.ok_or_else(|| io::Error::other("no stale feedback"))?;
        assert!(left.feedback_floor > 0 && right.source_floor > 0);
        // Fresh receiving fixtures authenticate these old generation-zero
        // bytes, isolating the epoch floors from ordinary replay rejection.
        right.open = protection::Receiver::new(&[1; 32], security::MAX_BODY_BYTES, KEY_PACKETS)
            .map_err(io::Error::other)?;
        left.open = protection::Receiver::new(&[2; 32], security::MAX_BODY_BYTES, KEY_PACKETS)
            .map_err(io::Error::other)?;
        let before = right.snapshot(now).receiver.duplicates;
        right.accept(now, &stale_source)?;
        assert_eq!(right.snapshot(now).receiver.duplicates, before + 1);
        left.accept(now, &stale_feedback)?;
        assert!(!right.deliverable());
        Ok(())
    }

    /// Refusals leave the session exactly as it was; messages that do not fit
    /// the state, a different derived configuration and a direction that
    /// cannot drain end it with an error.
    #[test]
    fn policy_change_refusals_and_violations_are_explicit() -> io::Result<()> {
        let policy = test_policy(2, 0, 1400, 16_000);
        let client = resolver(true);
        let server = resolver(false);
        let fresh = || -> io::Result<(Engine, Engine)> {
            let (mut left, right) = pair(2_500_000, 4)?;
            left.coordinator = true;
            Ok((left, right))
        };
        // Only the coordinator proposes, and only valid policies.
        let (mut left, mut right) = fresh()?;
        assert_eq!(
            right.request(0, policy, server(&policy)),
            Err(SwitchError::NotCoordinator)
        );
        let invalid = test_policy(0, 0, 1400, 16_000);
        assert_eq!(
            left.request(0, invalid, client(&invalid)),
            Err(SwitchError::Invalid)
        );
        assert!(left.outbox.is_empty() && left.change.is_none());
        // The peer refuses what it cannot derive; nothing changes and
        // forwarding continues.
        assert_eq!(left.request(0, policy, client(&policy)), Ok(()));
        let propose = left
            .outbox
            .pop_front()
            .ok_or_else(|| io::Error::other("no proposal"))?;
        let refuse =
            |_: &Policy| -> io::Result<Resolved> { Err(io::ErrorKind::Unsupported.into()) };
        right.on_control(0, propose, &refuse)?;
        assert_eq!(
            right.outbox.pop_front(),
            Some(Message::Reject {
                epoch: 1,
                reason: Refusal::Invalid
            })
        );
        left.on_control(
            0,
            Message::Reject {
                epoch: 1,
                reason: Refusal::Invalid,
            },
            &*client,
        )?;
        assert_eq!(left.outcome.take(), Some(Err(SwitchError::Rejected)));
        assert!(left.change.is_none() && right.change.is_none() && left.has_room());
        // A wrong epoch is refused; a repeated proposal gets the same answer;
        // a different one while busy is refused.
        right.on_control(0, Message::Propose { epoch: 5, policy }, &*server)?;
        assert_eq!(
            right.outbox.pop_front(),
            Some(Message::Reject {
                epoch: 5,
                reason: Refusal::Epoch
            })
        );
        right.on_control(0, propose, &*server)?;
        let accept = right.outbox.pop_front();
        assert!(matches!(accept, Some(Message::Accept { epoch: 1, .. })));
        right.on_control(0, propose, &*server)?;
        assert_eq!(right.outbox.pop_front(), accept);
        let other = test_policy(3, 0, 1400, 16_000);
        right.on_control(
            0,
            Message::Propose {
                epoch: 1,
                policy: other,
            },
            &*server,
        )?;
        assert_eq!(
            right.outbox.pop_front(),
            Some(Message::Reject {
                epoch: 1,
                reason: Refusal::Busy
            })
        );
        // Messages outside their state are violations.
        for message in [
            Message::Accept {
                epoch: 1,
                digest: [0; 32],
            },
            Message::Reject {
                epoch: 1,
                reason: Refusal::Busy,
            },
            Message::Barrier {
                epoch: 1,
                first_number: 0,
            },
            Message::BarrierAck {
                epoch: 1,
                feedback_from: 0,
            },
        ] {
            let (mut left, _) = fresh()?;
            assert!(
                left.on_control(0, message, &*client).is_err(),
                "{message:?}"
            );
        }
        let (mut left, _) = fresh()?;
        assert!(left.on_control(0, propose, &*client).is_err());
        // Agreement on a different configuration ends the session.
        let (mut left, _) = fresh()?;
        assert_eq!(left.request(0, policy, client(&policy)), Ok(()));
        let mismatch = Message::Accept {
            epoch: 1,
            digest: [0xEE; 32],
        };
        assert!(left.on_control(0, mismatch, &*client).is_err());
        // A barrier may not precede agreement, and an acknowledgement may
        // not precede the barrier.
        let (mut left, _) = fresh()?;
        assert_eq!(left.request(0, policy, client(&policy)), Ok(()));
        let early = Message::Barrier {
            epoch: 1,
            first_number: 0,
        };
        assert!(left.on_control(0, early, &*client).is_err());
        let (mut left, _) = fresh()?;
        assert_eq!(left.request(0, policy, client(&policy)), Ok(()));
        let digest = client(&policy)?.digest;
        left.on_control(0, Message::Accept { epoch: 1, digest }, &*client)?;
        let early = Message::BarrierAck {
            epoch: 1,
            feedback_from: 0,
        };
        assert!(left.on_control(0, early, &*client).is_err());
        // A direction whose peer never confirms cannot drain: the session
        // ends at the deadline instead of switching unilaterally.
        let (mut left, _) = fresh()?;
        left.offer(0, &segment(9, 0, 700))?;
        assert!(left.produce(1_000)?.is_some());
        assert_eq!(left.request(1_000, policy, client(&policy)), Ok(()));
        left.on_control(1_000, Message::Accept { epoch: 1, digest }, &*client)?;
        left.progress(2_000)?;
        assert!(
            left.outbox
                .iter()
                .all(|message| !matches!(message, Message::Barrier { .. }))
        );
        let deadline = 1_000 + DRAIN_TIMEOUT.as_micros() as u64;
        left.progress(deadline - 1)?;
        let error = left.progress(deadline).err();
        assert_eq!(
            error.map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        // A barrier that arrives while sources are still missing is refused.
        let (mut left, mut right) = fresh()?;
        left.offer(0, &segment(9, 0, 1300))?;
        left.offer(0, &segment(9, 1, 1300))?;
        let first = left.produce(1_000)?.map(<[u8]>::to_vec);
        let second = left.produce(1_000)?.map(<[u8]>::to_vec);
        assert!(first.is_some());
        right.accept(
            1_000,
            &second.ok_or_else(|| io::Error::other("one datagram"))?,
        )?;
        right.on_control(1_000, propose, &*server)?;
        right.on_control(
            1_000,
            Message::Barrier {
                epoch: 1,
                first_number: 9,
            },
            &*server,
        )?;
        // Nothing is deliverable: the first source never arrived.
        assert!(right.pop()?.is_none());
        assert!(right.progress(2_000).is_err());
        Ok(())
    }

    /// A peer that never answers the proposal cannot leave an operation
    /// pending indefinitely. User packets still cross under the old policy
    /// before the original deadline, and a late acceptance cannot commit it.
    #[test]
    fn policy_change_silent_proposal_preserves_old_data_until_original_deadline() -> io::Result<()>
    {
        let (mut left, mut right) = pair(2_500_000, 4)?;
        left.coordinator = true;
        let original = left.config;
        let policy = test_policy(2, 0, 1400, 16_000);
        let client = resolver(true);
        let started = 1_000;
        let deadline = started + DRAIN_TIMEOUT.as_micros() as u64;
        assert_eq!(left.request(started, policy, client(&policy)), Ok(()));
        assert!(left.has_room());
        let packet = segment(9, 0, 700);
        left.offer(started, &packet)?;
        let wire = left
            .produce(started + 1_000)?
            .ok_or_else(|| io::Error::other("no old-policy datagram"))?;
        right.accept(started + 1_000, wire)?;
        assert_eq!(right.pop()?, Some(packet.as_slice()));
        left.progress(deadline - 1)?;
        assert_eq!(left.config, original);
        assert_eq!(
            left.change.as_ref().map(|change| change.send),
            Some(SendPhase::Proposed)
        );
        assert_eq!(
            left.progress(deadline).err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        let digest = client(&policy)?.digest;
        assert_eq!(
            left.on_control(deadline, Message::Accept { epoch: 1, digest }, &*client)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(left.snapshot.policy_epoch, 0);
        assert!(left.snapshot.policy.is_none() && left.outcome.is_none());
        assert_eq!(left.config, original);
        Ok(())
    }

    /// Time waiting for acceptance belongs to the same transaction as the
    /// barrier wait. Silence after a barrier cannot gain another full bound.
    #[test]
    fn policy_change_silent_barrier_expires_at_original_proposal_deadline() -> io::Result<()> {
        let (mut left, _) = pair(2_500_000, 4)?;
        left.coordinator = true;
        let original = left.config;
        let policy = test_policy(2, 0, 1400, 16_000);
        let client = resolver(true);
        let started = 1_000;
        let deadline = started + DRAIN_TIMEOUT.as_micros() as u64;
        assert_eq!(left.request(started, policy, client(&policy)), Ok(()));
        let digest = client(&policy)?.digest;
        left.on_control(deadline - 2, Message::Accept { epoch: 1, digest }, &*client)?;
        left.progress(deadline - 1)?;
        assert_eq!(
            left.change.as_ref().map(|change| change.send),
            Some(SendPhase::Barrier)
        );
        assert!(
            left.outbox
                .iter()
                .any(|message| matches!(message, Message::Barrier { epoch: 1, .. }))
        );
        assert_eq!(left.wake(deadline - 1), Some(deadline));
        assert!(!left.has_room());
        assert_eq!(
            left.progress(deadline).err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(
            left.on_control(
                deadline,
                Message::BarrierAck {
                    epoch: 1,
                    feedback_from: 0,
                },
                &*client,
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(left.config, original);
        assert_eq!(left.snapshot.policy_epoch, 0);
        assert!(left.snapshot.policy.is_none() && left.outcome.is_none());
        Ok(())
    }

    /// An acceptor holding actual deliverable old data must finish flushing
    /// under its original proposal deadline. Identical proposals keep their
    /// idempotent reply but cannot renew the deadline or report a commit.
    #[test]
    fn policy_change_duplicate_proposal_cannot_renew_receive_flush_deadline() -> io::Result<()> {
        let (mut left, mut right) = pair(2_500_000, 4)?;
        let original = right.receive;
        let packet = segment(9, 0, 700);
        left.offer(0, &packet)?;
        let wire = left
            .produce(1_000)?
            .ok_or_else(|| io::Error::other("no datagram before the proposal"))?;
        right.accept(1_000, wire)?;
        assert!(right.deliverable());
        let policy = test_policy(2, 0, 1400, 16_000);
        let server = resolver(false);
        let proposal = Message::Propose { epoch: 1, policy };
        let deadline = 1_000 + DRAIN_TIMEOUT.as_micros() as u64;
        right.on_control(1_000, proposal, &*server)?;
        let accepted = right.outbox.pop_front();
        right.on_control(
            1_000,
            Message::Barrier {
                epoch: 1,
                first_number: left.seal.next_number().0,
            },
            &*server,
        )?;
        right.progress(deadline - 1)?;
        assert!(matches!(
            right.change.as_ref().map(|change| change.receive),
            Some(ReceivePhase::Flushing { .. })
        ));
        right.outbox.clear();
        right.on_control(deadline - 1, proposal, &*server)?;
        assert_eq!(right.outbox.pop_front(), accepted);
        assert_eq!(
            right.change.as_ref().map(|change| change.deadline),
            Some(deadline)
        );
        assert_eq!(
            right.progress(deadline).err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(right.receive, original);
        assert_eq!(right.snapshot.policy_epoch, 0);
        assert!(right.snapshot.policy.is_none() && right.outcome.is_none());
        assert_eq!(right.pop()?, Some(packet.as_slice()));
        Ok(())
    }

    /// An otherwise idle tunnel carrying one full-size frame every 200 ms
    /// each way over a 35 ms, 15% loss path: every frame must arrive, and
    /// none may wait long enough to look lost to its application.
    #[test]
    fn sparse_full_size_frames_on_a_lossy_idle_path_are_never_stalled() -> io::Result<()> {
        let mut config = config(12_375_000, 16);
        config.codec.flush_micros = 1_000;
        config.codec.flow_sources = 4096;
        config.codec.queue_bytes = 250_000;
        let (a, b) = ([1; 32], [2; 32]);
        let mut left = Engine::new(
            config,
            &Keys {
                send: &a,
                receive: &b,
            },
            0,
        )?;
        let mut right = Engine::new(
            config,
            &Keys {
                send: &b,
                receive: &a,
            },
            0,
        )?;
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // (arrival time, wire) per direction.
        let mut links: [VecDeque<(u64, Vec<u8>)>; 2] = [VecDeque::new(), VecDeque::new()];
        let mut sent_at: [Vec<u64>; 2] = [Vec::new(), Vec::new()];
        let mut worst = 0u64;
        let mut delivered = [0usize; 2];
        let frames = 3_000u32;
        let mut now = 0u64;
        while now < u64::from(frames) * 200_000 + 5_000_000 {
            now += 500;
            if now.is_multiple_of(200_000) && sent_at[0].len() < frames as usize {
                for (side, engine) in [&mut left, &mut right].into_iter().enumerate() {
                    engine.offer(now, &segment(0, sent_at[side].len() as u32, 1500))?;
                    sent_at[side].push(now);
                }
            }
            for side in 0..2 {
                let (from, to) = if side == 0 {
                    (&mut left, &mut right)
                } else {
                    (&mut right, &mut left)
                };
                while let Some(wire) = from.produce(now)? {
                    if random() % 100 >= 15 {
                        links[side].push_back((now + 35_000, wire.to_vec()));
                    }
                }
                while links[side].front().is_some_and(|(at, _)| *at <= now) {
                    if let Some((_, wire)) = links[side].pop_front() {
                        to.accept(now, &wire)?;
                    }
                }
                while let Some(packet) = to.pop()? {
                    let index = counter_of(packet) as usize;
                    assert_eq!(index, delivered[side], "out of order");
                    delivered[side] += 1;
                    worst = worst.max(now - sent_at[side][index]);
                }
            }
        }
        assert_eq!(delivered, [frames as usize; 2]);
        assert!(worst < 1_500_000, "a frame waited {worst} us");
        Ok(())
    }

    #[test]
    fn inconsistent_authenticated_bodies_end_the_session() -> io::Result<()> {
        let (_, mut right) = pair(12_500_000, 4)?;
        let mut sender = protection::Sender::new(&[1; 32], security::MAX_BODY_BYTES, KEY_PACKETS)
            .map_err(io::Error::other)?;
        let mut skipped = [0; PROTECTION_BYTES + 1];
        for _ in 0..100 {
            sender.seal(&[0], &mut skipped).map_err(io::Error::other)?;
        }
        let mut send = |body: &[u8], number: u64| -> io::Result<Vec<u8>> {
            assert_eq!(sender.next_number().0, number);
            let mut wire = vec![0; body.len() + PROTECTION_BYTES];
            sender.seal(body, &mut wire).map_err(io::Error::other)?;
            Ok(wire)
        };
        let bodies: [&[u8]; 5] = [
            // channel 5 of 4
            &[tagged(codec::KIND_SOURCE, 5), 0, 0, 0, 0, 1],
            // feedback block shorter than its header
            &[tagged(codec::KIND_FEEDBACK, 1), 0, 0],
            // feedback block announcing requests it does not carry
            &[
                tagged(codec::KIND_FEEDBACK, 1),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                3,
            ],
            // a second block that is not feedback
            &[
                tagged(codec::KIND_FEEDBACK, 1),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                1,
            ],
            // unknown kind
            &[3, 0, 0, 0, 0, 1],
        ];
        for (number, body) in bodies.iter().enumerate() {
            let wire = send(body, 100 + number as u64)?;
            let error = right.accept(1, &wire).err();
            assert_eq!(
                error.map(|error| error.kind()),
                Some(io::ErrorKind::InvalidData),
                "{body:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn pacing_holds_the_long_term_rate_and_reports_the_next_send_time() -> io::Result<()> {
        // 1 Mbit/s of IP bytes.
        let (mut left, _) = pair(125_000, 2)?;
        let mut sent = 0u64;
        let mut now = 0;
        while now <= 2_000_000 {
            while left.has_room() {
                left.offer(now, &[7; 1500])?;
            }
            while let Some(wire) = left.produce(now)? {
                sent += (wire.len() + 28) as u64;
            }
            let wake = left.wake(now).ok_or_else(|| io::Error::other("no wake"))?;
            assert!(wake > now, "busy wake at {now}");
            now = wake;
        }
        // Two seconds of budget plus the initial burst allowance.
        let expected = 250_000;
        assert!(
            sent >= expected && sent <= expected + 2 * 1500 + 3000,
            "{sent}"
        );
        assert_eq!(left.snapshot(now).ip_bytes_sent, sent);
        // The shared queue budget refuses more input instead of growing.
        while left.has_room() {
            left.offer(now, &[7; 1500])?;
        }
        let before = left.snapshot(now).native_dropped;
        left.offer(now, &[7; 1500])?;
        assert_eq!(left.snapshot(now).native_dropped, before + 1);
        Ok(())
    }

    /// A datagram socket standing in for a TAP/TUN descriptor.
    struct Pipe(std::os::unix::net::UnixDatagram);
    impl AsRawFd for Pipe {
        fn as_raw_fd(&self) -> std::os::fd::RawFd {
            self.0.as_raw_fd()
        }
    }
    impl PacketDevice for Pipe {
        type Error = io::Error;
        fn layer(&self) -> PacketLayer {
            PacketLayer::Ip
        }
        fn receive(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
            match self.0.recv(buffer) {
                Ok(length) => Ok(Some(length)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(error),
            }
        }
        fn transmit(&mut self, packet: &[u8]) -> io::Result<()> {
            self.0.send(packet).map(drop)
        }
    }

    struct DeadlineRuntime {
        task: tokio::task::JoinHandle<io::Result<()>>,
        switch: Switcher,
        peer: tokio::io::DuplexStream,
        reports: std::sync::Arc<std::sync::Mutex<Vec<Snapshot>>>,
        _application: std::os::unix::net::UnixDatagram,
        _udp_peer: UdpSocket,
    }

    async fn deadline_runtime(control_capacity: usize) -> io::Result<DeadlineRuntime> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_peer = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(udp_peer.local_addr()?).await?;
        udp_peer.connect(socket.local_addr()?).await?;
        let (device, application) = std::os::unix::net::UnixDatagram::pair()?;
        device.set_nonblocking(true)?;
        let (control, peer) = tokio::io::duplex(control_capacity);
        let (switch, requests) = switcher();
        let reports = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = reports.clone();
        let task = tokio::spawn(async move {
            run(
                Pipe(device),
                socket,
                Keys {
                    send: &[5; 32],
                    receive: &[6; 32],
                },
                config(2_500_000, 4),
                control,
                Switching {
                    coordinator: true,
                    requests: Some(requests),
                    resolve: resolver(true),
                },
                move |snapshot| {
                    sink.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(*snapshot);
                },
            )
            .await
        });
        Ok(DeadlineRuntime {
            task,
            switch,
            peer,
            reports,
            _application: application,
            _udp_peer: udp_peer,
        })
    }

    async fn read_control(peer: &mut tokio::io::DuplexStream) -> io::Result<Message> {
        let mut prefix = [0; 2];
        peer.read_exact(&mut prefix).await?;
        let length = usize::from(u16::from_be_bytes(prefix));
        if length + prefix.len() > codec::control::MAX_FRAME {
            return Err(io::Error::other("oversized test control message"));
        }
        let mut frame = vec![0; length + prefix.len()];
        frame[..prefix.len()].copy_from_slice(&prefix);
        peer.read_exact(&mut frame[prefix.len()..]).await?;
        Message::decode(&frame)
            .map_err(protocol)?
            .map(|(message, _)| message)
            .ok_or_else(|| io::Error::other("incomplete test control message"))
    }

    async fn write_control(peer: &mut tokio::io::DuplexStream, message: Message) -> io::Result<()> {
        let mut frame = Vec::new();
        message.encode(&mut frame);
        peer.write_all(&frame).await
    }

    /// An otherwise silent real runtime must wake at the original policy
    /// deadline in both proposal and barrier waits, emit its terminal report
    /// and close the requester without reporting an applied epoch.
    #[tokio::test(start_paused = true)]
    async fn runtime_policy_change_silence_expires_and_reports_at_original_deadline()
    -> io::Result<()> {
        for barrier in [false, true] {
            let mut runtime = deadline_runtime(128).await?;
            let started = Instant::now();
            let policy = test_policy(2, 0, 1400, 16_000);
            let switch = runtime.switch.clone();
            let change = tokio::spawn(async move { switch.switch(policy).await });
            assert!(matches!(
                read_control(&mut runtime.peer).await?,
                Message::Propose { epoch: 1, .. }
            ));
            tokio::time::advance(DRAIN_TIMEOUT - Duration::from_millis(1)).await;
            if barrier {
                write_control(
                    &mut runtime.peer,
                    Message::Accept {
                        epoch: 1,
                        digest: resolver(true)(&policy)?.digest,
                    },
                )
                .await?;
                assert!(matches!(
                    read_control(&mut runtime.peer).await?,
                    Message::Barrier { epoch: 1, .. }
                ));
            }
            assert!(!runtime.task.is_finished() && !change.is_finished());
            tokio::time::advance(Duration::from_millis(1)).await;
            let result = tokio::time::timeout(Duration::from_millis(1), runtime.task)
                .await
                .map_err(io::Error::other)?
                .map_err(io::Error::other)?;
            assert_eq!(
                result.err().map(|error| error.kind()),
                Some(io::ErrorKind::TimedOut)
            );
            assert_eq!(Instant::now().duration_since(started), DRAIN_TIMEOUT);
            assert_eq!(
                change.await.map_err(io::Error::other)?,
                Err(SwitchError::Closed)
            );
            let reports = runtime
                .reports
                .lock()
                .map_err(|_| io::Error::other("reports poisoned"))?;
            assert_eq!(reports.len(), 1, "timeout skipped the terminal report");
            assert_eq!(reports[0].elapsed_micros, DRAIN_TIMEOUT.as_micros() as u64);
            assert_eq!(reports[0].policy_epoch, 0);
            assert!(reports[0].policy.is_none());
        }
        Ok(())
    }

    /// Both directions can change locally before the terminal acknowledgement
    /// finishes writing. A blocked final write still shares the original
    /// deadline and cannot publish a successful committed epoch or roll back.
    #[tokio::test(start_paused = true)]
    async fn runtime_policy_change_blocked_terminal_ack_keeps_original_deadline() -> io::Result<()>
    {
        let mut runtime = deadline_runtime(1).await?;
        let started = Instant::now();
        let policy = test_policy(2, 0, 1400, 16_000);
        let switch = runtime.switch.clone();
        let change = tokio::spawn(async move { switch.switch(policy).await });
        assert!(matches!(
            read_control(&mut runtime.peer).await?,
            Message::Propose { epoch: 1, .. }
        ));
        write_control(
            &mut runtime.peer,
            Message::Accept {
                epoch: 1,
                digest: resolver(true)(&policy)?.digest,
            },
        )
        .await?;
        assert!(matches!(
            read_control(&mut runtime.peer).await?,
            Message::Barrier { epoch: 1, .. }
        ));
        tokio::time::advance(DRAIN_TIMEOUT - Duration::from_millis(1)).await;
        write_control(
            &mut runtime.peer,
            Message::BarrierAck {
                epoch: 1,
                feedback_from: 0,
            },
        )
        .await?;
        write_control(
            &mut runtime.peer,
            Message::Barrier {
                epoch: 1,
                first_number: 0,
            },
        )
        .await?;
        // Observe the start of the terminal BarrierAck, then stop reading.
        // The one-byte control buffer cannot hold its remaining frame.
        let mut first = [0; 1];
        runtime.peer.read_exact(&mut first).await?;
        assert_eq!(first, [0]);
        assert!(!runtime.task.is_finished() && !change.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        let result = tokio::time::timeout(Duration::from_millis(1), runtime.task)
            .await
            .map_err(io::Error::other)?
            .map_err(io::Error::other)?;
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        assert_eq!(Instant::now().duration_since(started), DRAIN_TIMEOUT);
        assert_eq!(
            change.await.map_err(io::Error::other)?,
            Err(SwitchError::Closed)
        );
        let reports = runtime
            .reports
            .lock()
            .map_err(|_| io::Error::other("reports poisoned"))?;
        assert_eq!(
            reports.len(),
            1,
            "write timeout skipped the terminal report"
        );
        assert_eq!(reports[0].policy_epoch, 0);
        assert!(reports[0].policy.is_none());
        Ok(())
    }

    /// Two complete runtimes over real loopback UDP sockets and readiness-
    /// driven descriptors: every packet crosses in both directions, exactly
    /// and in per-connection order, across two negotiated policy changes, and
    /// closing the control stream ends both cleanly.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_runtimes_forward_both_ways_over_loopback_and_stop_on_liveness() -> io::Result<()> {
        use std::os::unix::net::UnixDatagram;
        use std::sync::{Arc, Mutex};
        let left_udp = UdpSocket::bind("127.0.0.1:0").await?;
        let right_udp = UdpSocket::bind("127.0.0.1:0").await?;
        left_udp.connect(right_udp.local_addr()?).await?;
        right_udp.connect(left_udp.local_addr()?).await?;
        let mut applications = Vec::new();
        let mut tasks = Vec::new();
        let mut finals = Vec::new();
        // The control stream of each runtime, joined by a relay the test can
        // stop: closing it is the peers' liveness signal.
        let (left_control, left_relay) = tokio::io::duplex(1024);
        let (right_control, right_relay) = tokio::io::duplex(1024);
        let relay = tokio::spawn(async move {
            let (mut left, mut right) = (left_relay, right_relay);
            let _ = tokio::io::copy_bidirectional(&mut left, &mut right).await;
        });
        let (switch, requests) = switcher();
        let mut requests = Some(requests);
        for (socket, send, receive, control, coordinator) in [
            (left_udp, [5u8; 32], [6u8; 32], left_control, true),
            (right_udp, [6; 32], [5; 32], right_control, false),
        ] {
            let (device, application) = UnixDatagram::pair()?;
            device.set_nonblocking(true)?;
            application.set_nonblocking(true)?;
            applications.push(tokio::net::UnixDatagram::from_std(application)?);
            let switching = Switching {
                coordinator,
                requests: if coordinator { requests.take() } else { None },
                resolve: resolver(coordinator),
            };
            let last = Arc::new(Mutex::new(Snapshot::default()));
            finals.push(last.clone());
            let mut policy = config(2_500_000, 8);
            policy.codec.flush_micros = 500;
            policy.report_interval = Some(Duration::from_millis(100));
            tasks.push(tokio::spawn(async move {
                let keys = Keys {
                    send: &send,
                    receive: &receive,
                };
                run(
                    Pipe(device),
                    socket,
                    keys,
                    policy,
                    control,
                    switching,
                    |snapshot| {
                        if let Ok(mut slot) = last.lock() {
                            *slot = *snapshot;
                        }
                    },
                )
                .await
            }));
        }
        let mut buffer = vec![0u8; 2048];
        let limit = Duration::from_secs(20);
        let mut changes = Vec::new();
        for round in 0..150u32 {
            // Two negotiated changes while traffic flows in both directions:
            // fewer channels with repairs, then a smaller MTU with more
            // channels and a different budget.
            if round == 50 || round == 100 {
                let switch = switch.clone();
                let policy = if round == 50 {
                    test_policy(3, 300, 1500, 16_000)
                } else {
                    test_policy(16, 0, 1280, 24_000)
                };
                changes.push(tokio::spawn(async move { switch.switch(policy).await }));
            }
            // Eight connections each way per round, then collect all sixteen.
            for port in 0..8u16 {
                let length = 60 + ((round as usize * 37 + usize::from(port) * 211) % 1400);
                applications[0].send(&segment(port, round, length)).await?;
                applications[1]
                    .send(&segment(100 + port, round, length))
                    .await?;
            }
            for (side, base) in [(1usize, 0u16), (0, 100)] {
                let mut seen = [false; 8];
                for _ in 0..8 {
                    let received =
                        tokio::time::timeout(limit, applications[side].recv(&mut buffer)).await;
                    let Ok(length) = received else {
                        // Surface why: a stopped runtime, or the counters of a live one.
                        let mut detail = format!("round {round} side {side}:");
                        for (task, last) in tasks.into_iter().zip(&finals) {
                            if task.is_finished() {
                                detail.push_str(&format!(" finished {:?};", task.await));
                            } else {
                                detail
                                    .push_str(&format!(" running {:?};", last.lock().map(|v| *v)));
                            }
                        }
                        return Err(io::Error::other(detail));
                    };
                    let length = length?;
                    let (port, value) = counter(&buffer[..length]);
                    let index = usize::from(port - base);
                    assert_eq!(value, round, "connection {port} out of order");
                    assert_eq!(
                        buffer[..length],
                        segment(
                            port,
                            round,
                            60 + ((round as usize * 37 + index * 211) % 1400)
                        )[..]
                    );
                    assert!(!std::mem::replace(&mut seen[index], true), "duplicate");
                }
            }
        }
        let mut epochs = Vec::new();
        for change in changes {
            epochs.push(
                tokio::time::timeout(limit, change)
                    .await
                    .map_err(|_| io::Error::other("change did not complete"))?
                    .map_err(io::Error::other)?,
            );
        }
        assert_eq!(epochs, [Ok(1), Ok(2)]);
        // A retry of the policy in force is a completed no-op.
        assert_eq!(switch.switch(test_policy(16, 0, 1280, 24_000)).await, Ok(2));
        assert_eq!(
            switch.switch(test_policy(0, 0, 1280, 24_000)).await,
            Err(SwitchError::Invalid)
        );
        // Let both sides publish the committed epoch.
        tokio::time::sleep(Duration::from_millis(300)).await;
        relay.abort();
        for task in tasks {
            tokio::time::timeout(limit, task)
                .await
                .map_err(|_| io::Error::other("runtime did not stop"))?
                .map_err(io::Error::other)??;
        }
        for last in finals {
            let report = *last.lock().map_err(|_| io::Error::other("poisoned"))?;
            assert_eq!(report.native_read, 1200);
            assert_eq!(report.native_written, 1200);
            assert_eq!(report.datagrams_rejected, 0);
            assert_eq!(report.policy_epoch, 2);
            assert_eq!(report.policy, Some(test_policy(16, 0, 1280, 24_000)));
            assert!(report.sender.sources > 0 && report.receiver.feedback > 0);
        }
        Ok(())
    }

    #[test]
    fn only_path_conditions_are_treated_as_datagram_loss() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::NetworkDown,
        ] {
            assert!(path_loss(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NotConnected,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::Other,
        ] {
            assert!(!path_loss(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn invalid_runtime_configuration_is_rejected() {
        let changes: [fn(&mut Config); 7] = [
            |value| value.send_bytes_per_second = 10,
            |value| value.network_overhead = 0,
            |value| value.report_interval = Some(Duration::from_millis(1)),
            |value| value.codec.window = 0,
            |value| value.channels = 0,
            |value| value.channels = 65,
            |value| value.max_native = 1601,
        ];
        for change in changes {
            let mut bad = config(1_000_000, 4);
            change(&mut bad);
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(config(1_000_000, 64).validate().is_ok());
    }
}

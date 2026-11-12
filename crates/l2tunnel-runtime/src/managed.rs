//! Coordinated compression reload on actual authenticated full or paired-half TLS links.
//! Native devices must be nonblocking. The local API only proposes changes; completion
//! requires peer staging, real delivery fences, commit acknowledgement and retirement.
use super::*;
use l2tunnel_auth::{SessionConfig, SessionInfo};
use l2tunnel_core::{ConfigDigest, ModeConfig, PayloadCompression};
use l2tunnel_management::transaction::{self, Effects, Event, Fence, Identity, Peer, Phase, Tick};
use l2tunnel_management::{EndpointId, Ingress, LaneId, SessionId};
use std::collections::VecDeque;
use std::fmt;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

mod delivery;
/// Optional bounded observations of the original retained TCP/TLS path.
pub mod profiling;
pub use delivery::{DeliveryConfig, mode_config_with_delivery, session_config_with_delivery};
use profiling::{Counter as PC, HighWater as PH, Stage as PS};
pub use profiling::{
    ProfileHandle, ProfileSink, ProfileSnapshot, ProfileTiming, channel as profiling_channel,
};

/// Authenticated initiator/listener role; client is the sole reload coordinator.
pub use l2tunnel_management::Role;
/// Timeouts for the distributed transaction, in monotonic milliseconds.
pub use l2tunnel_management::transaction::Settings as TransactionSettings;

const CONTROL_SLOTS: usize = 8;
const CONTROL_BYTES: usize = 4096;
const CONTROL_RATE: usize = 256;

pub(crate) struct LinkMetadata {
    config: SessionConfig,
    role: Role,
    duplex: Duplex,
}
impl LinkMetadata {
    pub(crate) fn snapshot(&self) -> (SessionConfig, Role, Duplex) {
        (self.config, self.role, self.duplex)
    }

    pub(crate) fn new(info: &SessionInfo, duplex: Duplex) -> Self {
        Self {
            config: info.config,
            role: if info.peer_member.is_some() {
                Role::Server
            } else {
                Role::Client
            },
            duplex,
        }
    }
}

/// Configuration bound to authentication and the implemented mode subset.
#[derive(Clone, Debug)]
pub struct ManagedConfig {
    /// Must agree with the role established by membership authentication.
    pub role: Role,
    /// Must exactly match `mode_config` and the authenticated initial digest.
    pub initial_mode: ModeConfig,
    /// Finite retry, precommit and reconciliation deadlines.
    pub transaction_settings: TransactionSettings,
}

/// Applied configuration after both drain barriers, commit acknowledgement and retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwitchOutcome {
    /// Newly active configuration generation.
    pub epoch: Epoch,
    /// Effective stateless compression policy.
    pub compression: Compression,
}

/// Local control submission/completion failure. Closed never implies a successful switch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlError {
    /// Another proposal is pending, or the bounded local request queue is full.
    Busy,
    /// The authenticated listener cannot initiate this coordinator-owned protocol.
    NotCoordinator,
    /// The proposal was safely aborted before commit.
    Aborted,
    /// The runtime ended or the caller's completion channel was cancelled.
    Closed,
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local control error: {self:?}")
    }
}
impl std::error::Error for ControlError {}

/// Latest bounded observation; local phase is not a claim of simultaneous peer state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// False after runtime termination; retained counters are the last local observation.
    pub running: bool,
    /// Locally active configuration generation.
    pub epoch: Epoch,
    /// Locally active packet compressor.
    pub compression: Compression,
    /// Local distributed transaction phase.
    pub phase: Phase,
    /// Cumulative native packets admitted across all epochs.
    pub admitted: u64,
    /// Cumulative admitted packets fully written and flushed to TLS.
    pub flushed: u64,
    /// Cumulative peer packets accepted by the local native device.
    pub delivered: u64,
    /// Authenticated cumulative peer-native delivery feedback for local packets.
    pub peer_delivered: u64,
}
struct Request {
    compression: Compression,
    reply: oneshot::Sender<Result<SwitchOutcome, ControlError>>,
}
/// Cloneable bounded local management handle; it never accepts raw network frames.
#[derive(Clone)]
pub struct ControlHandle {
    sender: mpsc::Sender<Request>,
    status: watch::Receiver<Option<Status>>,
}
impl ControlHandle {
    /// Submit a compression proposal without unbounded queueing, then await peer completion.
    pub async fn switch_compression(
        &self,
        compression: Compression,
    ) -> Result<SwitchOutcome, ControlError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .try_send(Request { compression, reply })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ControlError::Busy,
                mpsc::error::TrySendError::Closed(_) => ControlError::Closed,
            })?;
        response.await.map_err(|_| ControlError::Closed)?
    }
    /// Subscribe to coalesced status snapshots; `None` means the runtime has not started.
    pub fn subscribe(&self) -> watch::Receiver<Option<Status>> {
        self.status.clone()
    }
    /// Read the last local snapshot without waiting.
    pub fn status(&self) -> Option<Status> {
        self.status.borrow().clone()
    }
}
/// Unique local control endpoint consumed by `run_managed`.
pub struct ControlReceiver {
    requests: mpsc::Receiver<Request>,
    status: watch::Sender<Option<Status>>,
}
/// Allocate the fixed eight-slot local control queue and one coalesced status slot.
pub fn channel() -> (ControlHandle, ControlReceiver) {
    let (sender, requests) = mpsc::channel(CONTROL_SLOTS);
    let (status, snapshot) = watch::channel(None);
    (
        ControlHandle {
            sender,
            status: snapshot,
        },
        ControlReceiver { requests, status },
    )
}

/// Construct the only initially supported mode family for these runtime limits.
pub fn mode_config(runtime: RuntimeConfig, duplex: Duplex) -> io::Result<ModeConfig> {
    runtime.validate()?;
    Ok(ModeConfig {
        duplex,
        channels: 1,
        queue_frames: runtime.queue_packets,
        queue_bytes: runtime
            .max_packet
            .checked_mul(runtime.queue_packets)
            .ok_or_else(|| invalid("queue byte limit overflow"))?
            .max(65_535),
        compression: to_mode(runtime.compression),
        ..ModeConfig::default()
    })
}
/// Bind managed framing, native bounds and canonical initial mode before TLS authentication.
/// Every lane must authenticate with this exact result; unmanaged session digests are incompatible.
pub fn session_config(runtime: RuntimeConfig, mode: &ModeConfig) -> io::Result<SessionConfig> {
    if *mode != mode_config(runtime, mode.duplex)? {
        return Err(invalid("unsupported managed initial mode or queue budget"));
    }
    let canonical = transaction::encode_mode(mode).map_err(io::Error::other)?;
    let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
    hash.update(b"l2tunnel/managed-runtime/session/v1\0");
    hash.update(&[
        1,
        1,
        match runtime.layer {
            PacketLayer::Ethernet => 1,
            PacketLayer::Ip => 2,
        },
    ]);
    hash.update(
        &u64::try_from(runtime.max_packet)
            .map_err(io::Error::other)?
            .to_be_bytes(),
    );
    hash.update(&canonical);
    let digest = ConfigDigest(
        hash.finish()
            .as_ref()
            .try_into()
            .map_err(|_| invalid("digest size"))?,
    );
    Ok(SessionConfig {
        layer: runtime.layer,
        digest,
    })
}
fn to_mode(compression: Compression) -> PayloadCompression {
    match compression {
        Compression::None => PayloadCompression::Off,
        Compression::Lz4IfSmaller => PayloadCompression::Lz4,
    }
}
fn from_mode(compression: PayloadCompression) -> io::Result<Compression> {
    match compression {
        PayloadCompression::Off => Ok(Compression::None),
        PayloadCompression::Lz4 => Ok(Compression::Lz4IfSmaller),
        PayloadCompression::Zstd => Err(invalid("unsupported managed compression")),
    }
}
fn increment(value: u64) -> io::Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("session counter exhausted"))
}
fn tick(start: Instant) -> io::Result<Tick> {
    Ok(Tick(
        u64::try_from(start.elapsed().as_millis()).map_err(io::Error::other)?,
    ))
}

struct Record {
    received_at: Option<Instant>,
    header: Header,
    payload: Vec<u8>,
}
enum Incoming {
    Record(Record),
    Eof,
}
struct OutData {
    epoch: Epoch,
    payload: Vec<u8>,
    admitted: u64,
}
struct OutControl {
    sequence: u64,
    bytes: Vec<u8>,
}
// Logical requests are immutable; each retry still gets a fresh replay packet
// number. Retain a bounded copy until flush and compare the logical identity.
struct ControlSender {
    sender: mpsc::Sender<OutControl>,
    flushed: watch::Receiver<u64>,
    pending: VecDeque<OutControl>,
    next: u64,
}
impl ControlSender {
    fn send(&mut self, bytes: Vec<u8>) -> io::Result<()> {
        let limits = l2tunnel_management::Limits {
            max_frame_bytes: CONTROL_BYTES,
            ..l2tunnel_management::Limits::default()
        };
        let incoming =
            l2tunnel_management::Frame::decode(&bytes, limits).map_err(io::Error::other)?;
        let flushed = *self.flushed.borrow_and_update();
        while self
            .pending
            .front()
            .is_some_and(|entry| entry.sequence <= flushed)
        {
            self.pending.pop_front();
        }
        for entry in &self.pending {
            let existing = l2tunnel_management::Frame::decode(&entry.bytes, limits)
                .map_err(io::Error::other)?;
            if existing.header.request == incoming.header.request {
                let mut identity = incoming.header;
                identity.packet = existing.header.packet;
                if identity != existing.header || incoming.body != existing.body {
                    return Err(invalid("conflicting immutable management request"));
                }
                return Ok(());
            }
        }
        if self.pending.len() >= CONTROL_SLOTS || bytes.len() > CONTROL_BYTES {
            return Err(invalid("bounded distinct management send queue exhausted"));
        }
        let sequence = increment(self.next)?;
        self.sender
            .try_send(OutControl {
                sequence,
                bytes: bytes.clone(),
            })
            .map_err(|_| invalid("management writer closed or queue exhausted"))?;
        self.pending.push_back(OutControl { sequence, bytes });
        self.next = sequence;
        Ok(())
    }
}
struct Codecs {
    plain: FrameCodec,
    lz4: FrameCodec,
}
impl Codecs {
    fn new(runtime: RuntimeConfig) -> io::Result<Self> {
        Ok(Self {
            plain: RuntimeConfig {
                compression: Compression::None,
                ..runtime
            }
            .codec()?,
            lz4: RuntimeConfig {
                compression: Compression::Lz4IfSmaller,
                ..runtime
            }
            .codec()?,
        })
    }
    fn select(&self, mode: PayloadCompression) -> io::Result<&FrameCodec> {
        match mode {
            PayloadCompression::Off => Ok(&self.plain),
            PayloadCompression::Lz4 => Ok(&self.lz4),
            PayloadCompression::Zstd => Err(invalid("unsupported staged codec")),
        }
    }
}

// A long-lived framing future; cancellation only happens when the entire Link is torn down.
async fn read_records<R: AsyncRead + Unpin>(
    mut reader: R,
    session: [u8; 16],
    maximum: usize,
    sender: mpsc::Sender<Incoming>,
    profile: Option<ProfileSink>,
    delivery: bool,
) -> io::Result<()> {
    let mut expected = 0;
    loop {
        let read_span = profile.as_ref().map(|p| p.span(PS::RecordRead));
        let mut prefix = [0_u8; 4];
        if reader.read(&mut prefix[..1]).await? == 0 {
            sender
                .send(Incoming::Eof)
                .await
                .map_err(|_| invalid("managed receiver closed"))?;
            return std::future::pending::<io::Result<()>>().await;
        }
        reader.read_exact(&mut prefix[1..]).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        if !(wire::HEADER_LEN..=wire::HEADER_LEN + maximum.max(CONTROL_BYTES)).contains(&length) {
            return Err(invalid("managed record exceeds framing bound"));
        }
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        drop(read_span);
        let (header, payload) = {
            let _span = profile.as_ref().map(|p| p.span(PS::OuterDecode));
            wire::decode(&bytes, maximum.max(CONTROL_BYTES)).map_err(wire_error)?
        };
        if let Some(p) = &profile {
            p.count(PC::RecordsRead, 1);
            p.count(PC::RecordBytesRead, (length + 4) as u64);
            p.high(PH::RecordBytes, (length + 4) as u64);
        }
        if header.session != session || header.lane != 0 || header.packet_number != expected {
            return Err(invalid("managed record session or sequence mismatch"));
        }
        let valid = match header.kind {
            Kind::Data => payload.len() <= maximum && header.epoch.0 > 0,
            Kind::Control => payload.len() <= CONTROL_BYTES && header.epoch == Epoch(0),
            Kind::Feedback => payload.len() == 8 && header.epoch == Epoch(0),
            Kind::Repair => false,
        };
        if !valid {
            return Err(invalid("unsupported managed record kind or length"));
        }
        expected = increment(expected)?;
        let received_at = delivery.then(Instant::now);
        let send_span = profile.as_ref().map(|p| p.span(PS::IncomingQueue));
        sender
            .send(Incoming::Record(Record {
                received_at,
                header,
                payload: payload.to_vec(),
            }))
            .await
            .map_err(|_| invalid("managed receiver closed"))?;
        drop(send_span);
        if let Some(p) = &profile {
            p.high(
                PH::Incoming,
                (sender.max_capacity() - sender.capacity()) as u64,
            );
        }
    }
}
async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    session: [u8; 16],
    number: &mut u64,
    kind: Kind,
    epoch: Epoch,
    payload: &[u8],
    profile: Option<&ProfileSink>,
) -> io::Result<()> {
    let outer_span = profile.map(|p| p.span(PS::OuterEncode));
    let bytes = wire::encode(
        Header {
            kind,
            epoch,
            packet_number: *number,
            session,
            lane: 0,
        },
        payload,
    )
    .map_err(wire_error)?;
    drop(outer_span);
    *number = increment(*number)?;
    {
        let _span = profile.map(|p| p.span(PS::PrefixWrite));
        writer
            .write_u32(u32::try_from(bytes.len()).map_err(io::Error::other)?)
            .await?;
    }
    {
        let _span = profile.map(|p| p.span(PS::BodyWrite));
        writer.write_all(&bytes).await?;
    }
    {
        let _span = profile.map(|p| p.span(PS::Flush));
        writer.flush().await?;
    }
    if let Some(p) = profile {
        p.count(PC::RecordsFlushed, 1);
        p.count(PC::RecordBytesFlushed, (bytes.len() + 4) as u64);
        p.high(PH::RecordBytes, (bytes.len() + 4) as u64);
        match kind {
            Kind::Data => p.count(PC::DataFlushed, 1),
            Kind::Feedback => p.count(PC::FeedbackFlushed, 1),
            Kind::Control => p.count(PC::ControlFlushed, 1),
            Kind::Repair => {}
        }
    }
    Ok(())
}
struct WriterProgress {
    control: watch::Sender<u64>,
    credit: watch::Sender<u64>,
    data: watch::Sender<u64>,
    delivery: Option<mpsc::Sender<delivery::FlushEvent>>,
}
async fn write_records<W: AsyncWrite + Unpin>(
    mut writer: W,
    session: [u8; 16],
    mut data: mpsc::Receiver<OutData>,
    mut control: mpsc::Receiver<OutControl>,
    mut credit: watch::Receiver<u64>,
    progress: WriterProgress,
    profile: Option<ProfileSink>,
) -> io::Result<()> {
    enum Selected {
        Control(OutControl),
        Feedback(u64),
        Data(OutData),
    }
    let mut number = 0;
    loop {
        let wait = profile.as_ref().map(|p| p.span(PS::WriterWait));
        let selected = tokio::select! {
            biased;
            message = control.recv() => Selected::Control(message.ok_or_else(|| invalid("managed control producer stopped"))?),
            changed = credit.changed() => {
                changed.map_err(|_| invalid("delivery credit producer stopped"))?;
                Selected::Feedback(*credit.borrow_and_update())
            },
            packet = data.recv() => Selected::Data(packet.ok_or_else(|| invalid("managed data producer stopped"))?),
        };
        drop(wait);
        match selected {
            Selected::Control(message) => {
                if let Some(p) = &profile {
                    p.count(PC::WriterWakeControl, 1);
                }
                write_record(
                    &mut writer,
                    session,
                    &mut number,
                    Kind::Control,
                    Epoch(0),
                    &message.bytes,
                    profile.as_ref(),
                )
                .await?;
                progress.control.send_replace(message.sequence);
            }
            Selected::Feedback(delivered) => {
                if let Some(p) = &profile {
                    p.count(PC::WriterWakeFeedback, 1);
                }
                write_record(
                    &mut writer,
                    session,
                    &mut number,
                    Kind::Feedback,
                    Epoch(0),
                    &delivered.to_be_bytes(),
                    profile.as_ref(),
                )
                .await?;
                progress.credit.send_replace(delivered);
            }
            Selected::Data(packet) => {
                if let Some(p) = &profile {
                    p.count(PC::WriterWakeData, 1);
                }
                write_record(
                    &mut writer,
                    session,
                    &mut number,
                    Kind::Data,
                    packet.epoch,
                    &packet.payload,
                    profile.as_ref(),
                )
                .await?;
                // Timestamp every original successful full flush before any later I/O.
                if let Some(events) = &progress.delivery {
                    events
                        .try_send(delivery::FlushEvent {
                            ordinal: packet.admitted,
                            at: Instant::now(),
                        })
                        .map_err(|_| {
                            invalid("bounded delivery flush event queue exhausted or closed")
                        })?;
                }
                progress.data.send_replace(packet.admitted);
            }
        }
    }
}

struct Driver {
    peer: Peer,
    codecs: Codecs,
    runtime: RuntimeConfig,
    origin: Ingress,
    role: Role,
    admitted: u64,
    delivered: u64,
    received: u64,
    peer_delivered: u64,
    drain: Option<(Fence, Fence)>,
    pending: Option<oneshot::Sender<Result<SwitchOutcome, ControlError>>>,
    control_out: ControlSender,
    native_pending: VecDeque<Vec<u8>>,
    delivery: Option<delivery::Window>,
    rate_start: Tick,
    controls_received: usize,
}
impl Driver {
    fn codec(&self) -> io::Result<&FrameCodec> {
        self.codecs.select(self.peer.active_config().compression)
    }
    fn effects(&mut self, mut effects: Effects, now: Tick) -> io::Result<()> {
        loop {
            if let Some(bytes) = effects.outbound {
                self.control_out.send(bytes)?;
            }
            match effects.event {
                Some(Event::Stage { config, .. }) => {
                    // Both stateless readers are retained from startup; select the real
                    // target before declaring its epoch ready, without deferred allocation.
                    self.codecs.select(config.compression)?;
                    let local = Fence::new(&[self.admitted]).map_err(io::Error::other)?;
                    effects = self.peer.staged(local, now).map_err(io::Error::other)?;
                }
                Some(Event::Drain { local, peer }) => {
                    self.drain = Some((local, peer));
                    break;
                }
                Some(Event::Retired(_)) => {
                    self.drain = None;
                    if let Some(reply) = self.pending.take() {
                        let _ = reply.send(Ok(SwitchOutcome {
                            epoch: self.peer.active_epoch(),
                            compression: from_mode(self.peer.active_config().compression)?,
                        }));
                    }
                    break;
                }
                Some(Event::Aborted(_)) => {
                    self.drain = None;
                    if let Some(reply) = self.pending.take() {
                        let _ = reply.send(Err(ControlError::Aborted));
                    }
                    break;
                }
                Some(Event::Failed) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "managed transaction reconciliation failed",
                    ));
                }
                Some(Event::Committed(_) | Event::Uncertain(_)) | None => break,
            }
        }
        Ok(())
    }
    fn request(&mut self, request: Request, now: Tick) -> io::Result<()> {
        let rejection = if self.role != Role::Client {
            Some(ControlError::NotCoordinator)
        } else if self.pending.is_some() || !self.peer.can_admit_data() {
            Some(ControlError::Busy)
        } else {
            None
        };
        if let Some(error) = rejection {
            let _ = request.reply.send(Err(error));
            return Ok(());
        }
        if to_mode(request.compression) == self.peer.active_config().compression {
            let _ = request.reply.send(Ok(SwitchOutcome {
                epoch: self.peer.active_epoch(),
                compression: request.compression,
            }));
            return Ok(());
        }
        let next = ModeConfig {
            compression: to_mode(request.compression),
            ..self.peer.active_config().clone()
        };
        let effects = self.peer.propose(next, now).map_err(io::Error::other)?;
        self.pending = Some(request.reply);
        self.effects(effects, now)
    }
    fn input(
        &mut self,
        record: Record,
        now: Tick,
        profile: Option<&ProfileSink>,
    ) -> io::Result<()> {
        match record.header.kind {
            Kind::Data => {
                if self.peer.active_config().compression == PayloadCompression::Off
                    && record.payload.get(4) != Some(&0)
                {
                    return Err(invalid("compressed data in an uncompressed epoch"));
                }
                if record.header.epoch != self.peer.active_epoch()
                    || (self.delivery.is_none()
                        && self.received.saturating_sub(self.delivered)
                            >= self.runtime.queue_packets as u64)
                {
                    return Err(invalid("data epoch or delivery-credit window violation"));
                }
                let reader = self
                    .peer
                    .reader(record.header.epoch)
                    .ok_or_else(|| invalid("retired data epoch"))?;
                if reader.disposition != transaction::ReadDisposition::Current {
                    return Err(invalid("data arrived after its completed drain barrier"));
                }
                let packet = {
                    let _span = profile.map(|p| p.span(PS::CodecDecode));
                    self.codec()?
                        .decode_vec(&record.payload)
                        .map_err(io::Error::other)?
                };
                if let Some(p) = profile {
                    p.count(PC::DecodeFrames, 1);
                    p.count(PC::DecodeBytes, packet.len() as u64);
                }
                if !packet_valid(self.runtime.layer, &packet) {
                    return Err(invalid("invalid managed native packet"));
                }
                if let Some(window) = &mut self.delivery {
                    window.receive(packet.len(), self.native_pending.len())?;
                }
                self.received = increment(self.received)?;
                self.native_pending.push_back(packet);
                if let Some(p) = profile {
                    p.high(PH::NativePending, self.native_pending.len() as u64);
                }
            }
            Kind::Feedback => {
                let delivered = u64::from_be_bytes(
                    record
                        .payload
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid("invalid credit frame"))?,
                );
                if delivered < self.peer_delivered || delivered > self.admitted {
                    return Err(invalid("invalid cumulative native delivery credit"));
                }
                if let Some(window) = &mut self.delivery {
                    window.feedback(
                        delivered,
                        record
                            .received_at
                            .ok_or_else(|| invalid("missing original feedback timestamp"))?,
                    )?;
                }
                self.peer_delivered = delivered;
            }
            Kind::Control => {
                if now.0.saturating_sub(self.rate_start.0) >= 1_000 {
                    self.rate_start = now;
                    self.controls_received = 0;
                }
                self.controls_received += 1;
                if self.controls_received > CONTROL_RATE {
                    return Err(invalid("management input service budget exceeded"));
                }
                let effects = match self.peer.receive(self.origin, &record.payload, now) {
                    Ok(effects) => effects,
                    Err(transaction::Error::Admission(
                        l2tunnel_management::Error::RequestRetired
                        | l2tunnel_management::Error::PacketReplay
                        | l2tunnel_management::Error::PacketTooOld,
                    )) => return Ok(()),
                    Err(error) => return Err(io::Error::other(error)),
                };
                self.effects(effects, now)?;
            }
            Kind::Repair => return Err(invalid("unsupported repair record")),
        }
        Ok(())
    }
    fn publish(&self, flushed: u64, status: &watch::Sender<Option<Status>>) -> io::Result<()> {
        status.send_replace(Some(Status {
            running: true,
            epoch: self.peer.active_epoch(),
            compression: from_mode(self.peer.active_config().compression)?,
            phase: self.peer.phase(),
            admitted: self.admitted,
            flushed,
            delivered: self.delivered,
            peer_delivered: self.peer_delivered,
        }));
        Ok(())
    }
}

struct DriverIo {
    incoming: mpsc::Receiver<Incoming>,
    outgoing: mpsc::Sender<OutData>,
    credit: watch::Sender<u64>,
    flushed: watch::Receiver<u64>,
    credit_flushed: watch::Receiver<u64>,
    local: ControlReceiver,
    delivery_flushes: Option<mpsc::Receiver<delivery::FlushEvent>>,
}

struct StatusLifetime(watch::Sender<Option<Status>>);
impl Drop for StatusLifetime {
    fn drop(&mut self) {
        self.0.send_modify(|snapshot| {
            if let Some(snapshot) = snapshot {
                snapshot.running = false;
            }
        });
    }
}
async fn drive<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    mut state: Driver,
    mut ports: DriverIo,
    profile: Option<ProfileSink>,
) -> io::Result<()> {
    let start = Instant::now();
    let mut timer =
        tokio::time::interval(state.runtime.poll_interval.min(Duration::from_millis(10)));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut buffer = vec![0; wire::MAX_PAYLOAD + 1];
    let mut local_open = true;
    let mut eof = None;
    let mut credit_blocked_span = None;
    state.publish(0, &ports.local.status)?;
    loop {
        if let Some(p) = &profile {
            p.count(PC::DriverIterations, 1);
        }
        let wait = profile.as_ref().map(|p| p.span(PS::DriverWait));
        enum Wake {
            Incoming(Incoming),
            Local(Option<Request>),
            DataFlush,
            DeliveryFlush(delivery::FlushEvent),
            FeedbackFlush,
            Timer,
        }
        let wake = tokio::select! {
            record = ports.incoming.recv() => Wake::Incoming(record.ok_or_else(|| invalid("managed carrier reader stopped"))?),
            request = ports.local.requests.recv(), if local_open && eof.is_none() => Wake::Local(request),
            changed = ports.flushed.changed() => { changed.map_err(|_| invalid("managed writer stopped"))?; Wake::DataFlush },
            changed = ports.credit_flushed.changed() => { changed.map_err(|_| invalid("managed feedback writer stopped"))?; Wake::FeedbackFlush },
            event = async { match &mut ports.delivery_flushes { Some(events) => events.recv().await, None => std::future::pending().await } } => Wake::DeliveryFlush(event.ok_or_else(|| invalid("delivery flush producer stopped"))?),
            _ = timer.tick() => Wake::Timer,
        };
        drop(wait);
        // Apply every original completion before processing newly observed feedback.
        // Original receipt times still exclude callbacks that happened afterward.
        if let Wake::DeliveryFlush(event) = &wake
            && let Some(window) = &mut state.delivery
        {
            window.flush(delivery::FlushEvent {
                ordinal: event.ordinal,
                at: event.at,
            })?;
        }
        if let (Some(window), Some(events)) = (&mut state.delivery, &mut ports.delivery_flushes) {
            // Static per-turn bound, even if a separately polled writer replenishes.
            for _ in 0..events.max_capacity() {
                let Ok(event) = events.try_recv() else {
                    break;
                };
                window.flush(event)?;
            }
        }
        match wake {
            Wake::Incoming(incoming) => {
                if let Some(p) = &profile {
                    p.count(PC::WakeIncoming, 1);
                }
                match incoming {
                    Incoming::Record(record) => {
                        state.input(record, tick(start)?, profile.as_ref())?
                    }
                    Incoming::Eof => eof = Some(tick(start)?),
                }
            }
            Wake::Local(request) => {
                if let Some(p) = &profile {
                    p.count(PC::WakeLocal, 1);
                }
                if let Some(request) = request {
                    state.request(request, tick(start)?)?;
                } else {
                    local_open = false;
                }
            }
            Wake::DeliveryFlush(_) | Wake::DataFlush => {
                if let Some(p) = &profile {
                    p.count(PC::WakeDataFlush, 1);
                }
            }
            Wake::FeedbackFlush => {
                if let Some(p) = &profile {
                    p.count(PC::WakeFeedbackFlush, 1);
                }
            }
            Wake::Timer => {
                if let Some(p) = &profile {
                    p.count(PC::WakeTimer, 1);
                }
            }
        }

        if let Some(p) = &profile {
            p.high(PH::Incoming, ports.incoming.len() as u64);
            p.high(
                PH::Outgoing,
                (ports.outgoing.max_capacity() - ports.outgoing.capacity()) as u64,
            );
            p.high(
                PH::Control,
                (state.control_out.sender.max_capacity() - state.control_out.sender.capacity())
                    as u64,
            );
            p.high(
                PH::Unconfirmed,
                state.admitted.saturating_sub(state.peer_delivered),
            );
            p.high(
                PH::Unflushed,
                state.admitted.saturating_sub(*ports.flushed.borrow()),
            );
            if state.delivery.is_none()
                && state.admitted.saturating_sub(state.peer_delivered)
                    >= state.runtime.queue_packets as u64
            {
                if credit_blocked_span.is_none() {
                    credit_blocked_span = Some(p.span(PS::CreditBlocked));
                }
            } else {
                credit_blocked_span = None;
            }
            p.publish(false);
        }
        if let Some(window) = &mut state.delivery {
            window.publish(profile.as_ref())?;
        }
        let now = tick(start)?;
        let effects = state.peer.poll(now).map_err(io::Error::other)?;
        state.effects(effects, now)?;
        for _ in 0..state.runtime.queue_packets.min(32) {
            let Some(packet) = state.native_pending.front() else {
                break;
            };
            if let Some(p) = &profile {
                p.count(PC::DeviceWriteCalls, 1);
            }
            let transmitted = {
                let _span = profile.as_ref().map(|p| p.span(PS::DeviceWrite));
                device.transmit(packet)
            };
            match transmitted {
                Ok(()) => {
                    if let Some(p) = &profile {
                        p.count(PC::DeviceWriteFrames, 1);
                        p.count(PC::DeviceWriteBytes, packet.len() as u64);
                        p.count(PC::FeedbackUpdates, 1);
                    }
                    if let Some(window) = &mut state.delivery {
                        window.pending_bytes = window
                            .pending_bytes
                            .checked_sub(packet.len() as u64)
                            .ok_or_else(|| invalid("native delivery byte accounting underflow"))?;
                    }
                    state.native_pending.pop_front();
                    state.delivered = increment(state.delivered)?;
                    ports.credit.send_replace(state.delivered);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if let Some(p) = &profile {
                        p.count(PC::DeviceWriteBlocked, 1);
                    }
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        let flushed = *ports.flushed.borrow_and_update();
        if let Some((local, remote)) = state.drain.as_ref() {
            if local.counts() != [state.admitted]
                || flushed > state.admitted
                || remote.counts()[0] < state.received
            {
                return Err(invalid(
                    "drain fence contradicts admitted or received records",
                ));
            }
            if local.counts() == [flushed] && remote.counts() == [state.delivered] {
                let effects = state
                    .peer
                    .confirm_drained(local, remote, now)
                    .map_err(io::Error::other)?;
                state.drain = None;
                state.effects(effects, now)?;
            }
        }
        if let Some(closed_at) = eof {
            state.publish(flushed, &ports.local.status)?;
            if state.native_pending.is_empty() {
                if state.peer.phase() != Phase::Idle
                    || state.peer_delivered != state.admitted
                    || state.delivery.as_ref().is_some_and(|w| w.staged.is_some())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "carrier closed with unfinished data or transaction",
                    ));
                }
                if *ports.credit_flushed.borrow_and_update() == state.delivered {
                    return Ok(());
                }
            }
            if now.0.saturating_sub(closed_at.0) >= 5_000 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native delivery or feedback flush remained blocked after carrier EOF",
                ));
            }
        }
        if state.peer.can_admit_data() && eof.is_none() {
            for _ in 0..state.runtime.queue_packets.min(32) {
                if state.delivery.is_none()
                    && state.admitted.saturating_sub(state.peer_delivered)
                        >= state.runtime.queue_packets as u64
                {
                    if let Some(p) = &profile {
                        p.count(PC::CreditBlocked, 1);
                    }
                    break;
                }
                let permit = match ports.outgoing.try_reserve() {
                    Ok(permit) => permit,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        if let Some(p) = &profile {
                            p.count(PC::QueueFull, 1);
                        }
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        return Err(invalid("managed data writer stopped"));
                    }
                };
                let staged = state.delivery.as_mut().and_then(|w| w.staged.take());
                let packet = if let Some(packet) = &staged {
                    packet.as_slice()
                } else {
                    if let Some(p) = &profile {
                        p.count(PC::DeviceReadCalls, 1);
                    }
                    let received = {
                        let _span = profile.as_ref().map(|p| p.span(PS::DeviceRead));
                        device.receive(&mut buffer)?
                    };
                    let Some(size) = received else {
                        if let Some(p) = &profile {
                            p.count(PC::DeviceReadNone, 1);
                        }
                        break;
                    };
                    if size > state.runtime.max_packet
                        || size > buffer.len()
                        || !packet_valid(state.runtime.layer, &buffer[..size])
                    {
                        return Err(invalid("invalid managed native input"));
                    }
                    if let Some(p) = &profile {
                        p.count(PC::DeviceReadFrames, 1);
                        p.count(PC::DeviceReadBytes, size as u64);
                        p.high(PH::NativeBytes, size as u64);
                    }
                    &buffer[..size]
                };
                if let Some(window) = &mut state.delivery {
                    if !window.admit(packet.len())? {
                        window.staged = if staged.is_some() {
                            staged
                        } else {
                            Some(packet.to_vec())
                        };
                        if let Some(p) = &profile {
                            p.count(PC::CreditBlocked, 1);
                            if credit_blocked_span.is_none() {
                                credit_blocked_span = Some(p.span(PS::CreditBlocked));
                            }
                        }
                        break;
                    }
                    credit_blocked_span = None;
                }
                let size = packet.len();
                let payload = {
                    let _span = profile.as_ref().map(|p| p.span(PS::CodecEncode));
                    state
                        .codec()?
                        .encode_vec(packet)
                        .map_err(io::Error::other)?
                };
                if let Some(p) = &profile {
                    p.count(PC::EncodeFrames, 1);
                    p.count(PC::EncodeBytes, size as u64);
                    p.count(PC::DataAdmitted, 1);
                }
                state.admitted = increment(state.admitted)?;
                permit.send(OutData {
                    epoch: state.peer.active_epoch(),
                    payload,
                    admitted: state.admitted,
                });
            }
        } else if let Some(p) = &profile {
            p.count(PC::AdmissionPaused, 1);
        }
        state.publish(flushed, &ports.local.status)?;
    }
}

/// Run an authenticated link with coordinated None/LZ4 changes and real native delivery barriers.
/// EOF or cancellation closes pending local requests; uncertain commits are never reported applied.
/// Both full duplex and paired half duplex are supported; other mode changes fail before startup.
pub async fn run_managed<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: ManagedConfig,
    local: ControlReceiver,
) -> io::Result<()> {
    run_managed_with_profile(device, link, runtime, config, local, None).await
}
/// Run the same retained path with optional bounded, non-authoritative observations.
/// Disabled profiling performs no profiling clock reads, allocation or publication.
pub async fn run_managed_with_profile<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: ManagedConfig,
    local: ControlReceiver,
    profile: Option<ProfileSink>,
) -> io::Result<()> {
    run_managed_inner(device, link, runtime, config, local, None, profile).await
}
/// Run an explicitly authenticated directional byte window on the retained path.
/// Local queues and original transaction deadlines remain independent and unchanged.
pub async fn run_managed_with_delivery<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: ManagedConfig,
    local: ControlReceiver,
    delivery: DeliveryConfig,
    profile: Option<ProfileSink>,
) -> io::Result<()> {
    run_managed_inner(
        device,
        link,
        runtime,
        config,
        local,
        Some(delivery),
        profile,
    )
    .await
}
async fn run_managed_inner<D: PacketDevice<Error = io::Error>>(
    device: D,
    link: Link,
    runtime: RuntimeConfig,
    config: ManagedConfig,
    local: ControlReceiver,
    delivery: Option<DeliveryConfig>,
    profile: Option<ProfileSink>,
) -> io::Result<()> {
    let _profile_lifetime = profiling::Lifetime(profile.clone());
    if let Some(p) = &profile {
        p.high(PH::LocalQueueLimit, runtime.queue_packets as u64);
        p.high(
            PH::DeliveryCreditLimit,
            delivery.map_or(runtime.queue_packets, |d| {
                d.outgoing(config.role).max_records
            }) as u64,
        );
    }
    let negotiated = match delivery {
        Some(delivery) => session_config_with_delivery(runtime, &config.initial_mode, delivery)?,
        None => session_config(runtime, &config.initial_mode)?,
    };
    let metadata = link
        .managed_metadata
        .as_ref()
        .ok_or_else(|| invalid("link lacks authenticated management metadata"))?;
    if metadata.config != negotiated
        || metadata.role != config.role
        || metadata.duplex != config.initial_mode.duplex
        || device.layer() != runtime.layer
        || link.layer != runtime.layer
    {
        return Err(invalid(
            "managed authenticated mode, role, duplex or native layer mismatch",
        ));
    }
    let session = SessionId(if config.role == Role::Client {
        link.send_session
    } else {
        link.receive_session
    });
    let identity = Identity {
        session,
        role: config.role,
        local: EndpointId(if config.role == Role::Client { 1 } else { 2 }),
        remote: EndpointId(if config.role == Role::Client { 2 } else { 1 }),
        lane: LaneId(0),
    };
    let mut supported = [config.initial_mode.clone(), config.initial_mode.clone()];
    supported[0].compression = PayloadCompression::Off;
    supported[1].compression = PayloadCompression::Lz4;
    // Retain both actual stateless readers before advertising either to Peer.
    let codecs = Codecs::new(runtime)?;
    let peer = Peer::new(
        identity,
        Epoch(1),
        config.initial_mode,
        &supported,
        config.transaction_settings,
        Tick(0),
    )
    .map_err(io::Error::other)?;
    let maximum = runtime.codec()?.max_encoded_len();
    let (in_tx, incoming) = mpsc::channel(runtime.queue_packets + CONTROL_SLOTS);
    let (outgoing, out_rx) = mpsc::channel(runtime.queue_packets);
    let (control_out, control_rx) = mpsc::channel(CONTROL_SLOTS);
    let (control_flushed, control_flushed_rx) = watch::channel(0);
    let (credit_flushed_tx, credit_flushed) = watch::channel(0);
    let (credit, credit_rx) = watch::channel(0);
    let (flushed_tx, flushed) = watch::channel(0);
    let _status_lifetime = StatusLifetime(local.status.clone());
    let window = delivery
        .map(|d| delivery::Window::new(d, config.role, Instant::now()))
        .transpose()?;
    let (delivery_tx, delivery_flushes) = match delivery {
        Some(d) => {
            let (tx, rx) = mpsc::channel(d.outgoing(config.role).max_records);
            (Some(tx), Some(rx))
        }
        None => (None, None),
    };
    let native_capacity = delivery.map_or(runtime.queue_packets, |d| {
        d.incoming(config.role).max_records
    });
    let mut native_pending = VecDeque::new();
    native_pending
        .try_reserve_exact(native_capacity)
        .map_err(io::Error::other)?;
    let driver = Driver {
        peer,
        codecs,
        runtime,
        origin: Ingress::AuthenticatedManagement {
            session,
            lane: LaneId(0),
            sender: if config.role == Role::Client {
                Role::Server
            } else {
                Role::Client
            },
        },
        role: config.role,
        admitted: 0,
        delivered: 0,
        received: 0,
        peer_delivered: 0,
        drain: None,
        pending: None,
        control_out: ControlSender {
            sender: control_out,
            flushed: control_flushed_rx,
            pending: VecDeque::with_capacity(CONTROL_SLOTS),
            next: 0,
        },
        native_pending,
        delivery: window,
        rate_start: Tick(0),
        controls_received: 0,
    };
    let _reverse_writer = link.reverse_writer;
    let reverse = async move {
        match link.reverse_reader {
            Some(mut stream) => {
                let mut byte = [0_u8];
                if stream.read(&mut byte).await? == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "paired reverse TLS lane closed",
                    ))
                } else {
                    Err(invalid("unexpected reverse managed application data"))
                }
            }
            None => std::future::pending::<io::Result<()>>().await,
        }
    };
    tokio::select! {
        result = reverse => result,
        result = read_records(link.reader, link.receive_session, maximum, in_tx, profile.clone(), delivery.is_some()) => result,
        result = write_records(link.writer, link.send_session, out_rx, control_rx, credit_rx, WriterProgress { control: control_flushed, credit: credit_flushed_tx, data: flushed_tx, delivery: delivery_tx }, profile.clone()) => result,
        result = drive(device, driver, DriverIo { incoming, outgoing, credit, flushed, credit_flushed, local, delivery_flushes }, profile.clone()) => result,
    }
}

#[cfg(test)]
mod control_backpressure_tests {
    use super::*;

    #[test]
    fn actual_peer_poll_retries_coalesce_while_writer_flush_is_stalled() -> io::Result<()> {
        let initial = ModeConfig {
            channels: 1,
            ..ModeConfig::default()
        };
        let next = ModeConfig {
            compression: PayloadCompression::Lz4,
            ..initial.clone()
        };
        let mut peer = Peer::new(
            Identity {
                session: SessionId([3; 16]),
                role: Role::Client,
                local: EndpointId(1),
                remote: EndpointId(2),
                lane: LaneId(0),
            },
            Epoch(1),
            initial.clone(),
            &[initial, next.clone()],
            TransactionSettings {
                retry_ms: 1,
                phase_timeout_ms: 10_000,
                reconcile_timeout_ms: 20_000,
            },
            Tick(0),
        )
        .map_err(io::Error::other)?;
        peer.propose(next, Tick(0)).map_err(io::Error::other)?;
        let first = peer
            .staged(Fence::new(&[0]).map_err(io::Error::other)?, Tick(0))
            .map_err(io::Error::other)?
            .outbound
            .ok_or_else(|| invalid("missing first actual Prepare"))?;
        let limits = l2tunnel_management::Limits::default();
        let first_frame =
            l2tunnel_management::Frame::decode(&first, limits).map_err(io::Error::other)?;
        let (sender, mut receiver) = mpsc::channel(CONTROL_SLOTS);
        let (flushed, observed) = watch::channel(0);
        let mut control = ControlSender {
            sender,
            flushed: observed,
            pending: VecDeque::new(),
            next: 0,
        };
        control.send(first.clone())?;
        // The writer has removed this frame from mpsc but has not completed
        // write/flush. The retained logical request must cover this interval.
        let writing = receiver.try_recv().map_err(io::Error::other)?;
        let mut last_packet = first_frame.header.packet;
        for tick in 1..=1_000 {
            let retry = peer
                .poll(Tick(tick))
                .map_err(io::Error::other)?
                .outbound
                .ok_or_else(|| invalid("missing actual timed retry"))?;
            let frame =
                l2tunnel_management::Frame::decode(&retry, limits).map_err(io::Error::other)?;
            assert_eq!(frame.header.request, first_frame.header.request);
            assert_eq!(frame.body, first_frame.body);
            assert!(frame.header.packet > last_packet);
            last_packet = frame.header.packet;
            assert_ne!(retry, first);
            control.send(retry)?;
        }
        assert_eq!(control.pending.len(), 1);
        assert_eq!(control.pending[0].bytes, first);
        assert_eq!(control.next, 1);
        assert!(receiver.try_recv().is_err());

        // Only actual flush acknowledgement permits another physical retry.
        flushed.send_replace(writing.sequence);
        let retry = peer
            .poll(Tick(1_001))
            .map_err(io::Error::other)?
            .outbound
            .ok_or_else(|| invalid("missing post-flush retry"))?;
        control.send(retry.clone())?;
        let accepted = receiver.try_recv().map_err(io::Error::other)?;
        assert_eq!(accepted.sequence, 2);
        assert_eq!(accepted.bytes, retry);
        assert_eq!(control.pending.len(), 1);
        let mut conflicting = retry;
        *conflicting
            .last_mut()
            .ok_or_else(|| invalid("missing Prepare body"))? ^= 1;
        assert!(control.send(conflicting).is_err());
        assert_eq!(control.pending.len(), 1);
        assert_eq!(control.next, 2);
        Ok(())
    }

    fn message(request: u64, packet: u64) -> Vec<u8> {
        let mut bytes = vec![0; l2tunnel_management::HEADER_LEN];
        bytes[..4].copy_from_slice(b"L2MC");
        bytes[4] = 1;
        bytes[5] = 2;
        bytes[6] = 2;
        bytes[8..12].copy_from_slice(&(l2tunnel_management::HEADER_LEN as u32).to_be_bytes());
        bytes[32..40].copy_from_slice(&packet.to_be_bytes());
        bytes[40..48].copy_from_slice(&request.to_be_bytes());
        bytes
    }

    #[test]
    fn retries_coalesce_until_real_flush_and_distinct_frames_remain_bounded() -> io::Result<()> {
        let (sender, mut receiver) = mpsc::channel(CONTROL_SLOTS);
        let (flushed, observed) = watch::channel(0);
        let mut control = ControlSender {
            sender,
            flushed: observed,
            pending: VecDeque::new(),
            next: 0,
        };
        let retry = message(7, 0);
        control.send(retry.clone())?;
        let writing = receiver.try_recv().map_err(io::Error::other)?;
        for packet in 1..1_000 {
            control.send(message(7, packet))?;
        }
        let mut conflicting = message(7, 1_001);
        conflicting[5] = 3;
        assert!(control.send(conflicting).is_err());
        assert_eq!(control.pending.len(), 1);
        assert!(receiver.try_recv().is_err());
        for marker in 0..CONTROL_SLOTS - 1 {
            control.send(message(marker as u64, 1_002 + marker as u64))?;
        }
        assert!(control.send(message(99, 2_000)).is_err());
        assert_eq!(control.pending.len(), CONTROL_SLOTS);
        flushed.send_replace(writing.sequence);
        control.send(retry.clone())?;
        assert_eq!(control.pending.len(), CONTROL_SLOTS);
        let mut last = 0;
        while let Ok(message) = receiver.try_recv() {
            last = message.sequence;
        }
        assert_eq!(last, 9);
        flushed.send_replace(last);
        control.send(retry)?;
        assert_eq!(control.pending.len(), 1);
        assert_eq!(receiver.try_recv().map_err(io::Error::other)?.sequence, 10);
        Ok(())
    }
}

#[cfg(test)]
#[path = "managed/profiling_tests.rs"]
mod profiling_tests;

#[cfg(test)]
#[path = "managed/delivery_tests.rs"]
mod delivery_tests;

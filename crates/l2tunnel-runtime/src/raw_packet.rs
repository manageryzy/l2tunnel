//! Explicit startup-only raw packet runtime over the original TLS/packet owners.
//!
//! All native input traverses the existing common MUX and TAP/TUN policy. Recovery
//! uses maintained selective repeat or Reliable/Cauchy; receipt and native delivery
//! remain independent. This module opens no descriptor and spawns no driver task.
use super::{Compression, Duplex, RuntimeConfig, invalid, packet_valid, udp};
use l2tunnel_auth::{ClientTls, MemberAllowlist, MemberKey, ServerTls, SessionConfig};
use l2tunnel_codec::{
    FRAGMENT_HEADER_BYTES, FragmentConfig, FragmentContext, Fragmenter, FrameCodec, MessageId,
    Reassembler, ReassemblyConfig, ReassemblyStatus, SessionId,
};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_device::{PacketDevice, PacketLayer};
use l2tunnel_pipeline::{self as pipeline, Pipeline, PipelineConfig};
use l2tunnel_raw_io::{
    PacketIo,
    handoff::pairing::{
        PairInfo, PairLane, RawInputs,
        packet::{self as carrier, PacketCarrier, PacketPhaseConfig},
    },
};
use l2tunnel_recovery::{ArqConfig, BufferSide, DATA_HEADER_BYTES, EndpointRole, RecoveryContext};
use l2tunnel_reliable::{self as reliable, OutboundBudget, RecordKind as RecoveryKind};
use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, Interval, MissedTickBehavior},
};

mod config;
/// Maintained selective-repeat or Reliable/Cauchy policy shared with other carriers.
pub use super::udp::RecoveryMode;
pub use config::Config;
const HEADER: usize = 8;
const MAGIC: &[u8; 4] = b"L2RP";

/// Local runtime lifecycle; Active does not prove simultaneous peer knowledge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Original authentication/packet transition is still being driven.
    Setup,
    /// The actual native/recovery loop owns the original committed carrier.
    Active,
    /// The owning setup/link/runtime ended or was cancelled.
    Stopped,
}
/// Exact logical observations, distinct from raw physical sends and recovery receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    /// Local owner lifecycle.
    pub phase: Phase,
    /// Complete native frames committed from common admission, by physical lane.
    pub admitted: [u64; 2],
    /// Fragment sources submitted to maintained recovery; retries do not increment it.
    pub sources: [u64; 2],
    /// Complete reassembled peer frames, including native output still blocked.
    pub received: [u64; 2],
    /// Complete frames actually accepted by the native device.
    pub delivered: [u64; 2],
    /// Authenticated cumulative peer native-delivery confirmation.
    pub peer_delivered: [u64; 2],
    /// Recovery/control records accepted by the carrier staging API, not physical sends.
    pub staged: [u64; 2],
    /// First terminal I/O category when an owning operation returned one.
    pub fault: Option<io::ErrorKind>,
}
impl Status {
    fn new() -> Self {
        Self {
            phase: Phase::Setup,
            admitted: [0; 2],
            sources: [0; 2],
            received: [0; 2],
            delivered: [0; 2],
            peer_delivered: [0; 2],
            staged: [0; 2],
            fault: None,
        }
    }
}
/// Exact unchanged original inputs returned only for local pre-attachment rejection.
pub struct StartFailure<I: PacketIo> {
    /// The original unpolled packet owners.
    pub inputs: Box<RawInputs<I>>,
    /// Invalid local configuration or actual packet-owner factory rejection.
    pub error: io::Error,
}
impl<I: PacketIo> fmt::Debug for StartFailure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<I: PacketIo> fmt::Display for StartFailure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl<I: PacketIo> std::error::Error for StartFailure<I> {}
/// Owns actual from-birth authentication and packet transition; drop is terminal.
pub struct Setup<'a, I: PacketIo + Send + 'static> {
    inner: Pin<Box<carrier::PacketSetup<'a, I>>>,
    config: Config,
    status: watch::Sender<Status>,
    done: bool,
}
impl<I: PacketIo + Send + 'static> Setup<'_, I> {
    /// Subscribe to one coalesced logical status; no native input is admitted here.
    pub fn subscribe(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }
}
impl<I: PacketIo + Send + 'static> Drop for Setup<'_, I> {
    fn drop(&mut self) {
        if !self.done {
            self.status.send_modify(|s| s.phase = Phase::Stopped);
        }
    }
}
impl<I: PacketIo + Send + 'static> Future for Setup<'_, I> {
    type Output = io::Result<Link<I>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(invalid("raw runtime setup already completed")));
        }
        match this.inner.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                this.done = true;
                match result {
                    Ok(carrier) => Poll::Ready(Ok(Link {
                        carrier: Some(carrier),
                        config: this.config,
                        status: this.status.clone(),
                    })),
                    Err(error) => {
                        let error = carrier_error(error);
                        this.status.send_modify(|s| {
                            s.phase = Phase::Stopped;
                            s.fault = Some(error.kind());
                        });
                        Poll::Ready(Err(error))
                    }
                }
            }
        }
    }
}
/// Typed committed raw link; no public constructor adopts an arbitrary carrier.
pub struct Link<I: PacketIo + Send + 'static> {
    carrier: Option<PacketCarrier<I>>,
    config: Config,
    status: watch::Sender<Status>,
}
impl<I: PacketIo + Send + 'static> Link<I> {
    /// Actual authenticated ordered lane information, never key/freeze authority.
    pub fn info(&self) -> Option<&PairInfo> {
        self.carrier.as_ref().map(PacketCarrier::info)
    }
    /// Immutable authenticated runtime/native/recovery policy.
    pub fn config(&self) -> Config {
        self.config
    }
    /// Subscribe to the bounded logical observation slot.
    pub fn subscribe(&self) -> watch::Receiver<Status> {
        self.status.subscribe()
    }
    /// Continue original control service while another peer's setup is pending.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.carrier.as_mut() {
            Some(c) => c.poll_progress(cx).map_err(carrier_error),
            None => Poll::Ready(Err(invalid("raw runtime link consumed"))),
        }
    }
}
impl<I: PacketIo + Send + 'static> Drop for Link<I> {
    fn drop(&mut self) {
        self.status.send_modify(|s| s.phase = Phase::Stopped);
    }
}
fn shape<I: PacketIo>(inputs: &RawInputs<I>) -> Duplex {
    match inputs {
        RawInputs::Full(_) => Duplex::Full,
        RawInputs::Half { .. } => Duplex::Half,
    }
}
fn before<I: PacketIo>(inputs: &RawInputs<I>, config: Config) -> io::Result<PacketPhaseConfig> {
    config.validate()?;
    if shape(inputs) != config.duplex {
        return Err(invalid("raw runtime duplex/input shape mismatch"));
    }
    let mut transport = config.transport;
    transport.pair.session = config.session_config()?;
    Ok(transport)
}
/// Create all actual client owners with native/MUX/recovery policy bound before TLS.
///
/// # Panics
/// The current Tokio runtime must have its time driver enabled.
pub fn begin_client<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    tls: &'a ClientTls,
    name: &'a str,
    member: &'a MemberKey,
    config: Config,
) -> Result<Setup<'a, I>, StartFailure<I>> {
    let transport = match before(&inputs, config) {
        Ok(c) => c,
        Err(error) => {
            return Err(StartFailure {
                inputs: Box::new(inputs),
                error,
            });
        }
    };
    let setup =
        carrier::begin_packet_client(inputs, tls, name, member, transport).map_err(|f| {
            StartFailure {
                inputs: f.inputs,
                error: carrier_error(f.error),
            }
        })?;
    let (status, _) = watch::channel(Status::new());
    Ok(Setup {
        inner: Box::pin(setup),
        config,
        status,
        done: false,
    })
}
/// Create all actual server owners; policy mismatch fails original authentication.
///
/// # Panics
/// The current Tokio runtime must have its time driver enabled.
pub fn begin_server<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    tls: &'a ServerTls,
    members: &'a MemberAllowlist,
    config: Config,
) -> Result<Setup<'a, I>, StartFailure<I>> {
    let transport = match before(&inputs, config) {
        Ok(c) => c,
        Err(error) => {
            return Err(StartFailure {
                inputs: Box::new(inputs),
                error,
            });
        }
    };
    let setup = carrier::begin_packet_server(inputs, tls, members, transport).map_err(|f| {
        StartFailure {
            inputs: f.inputs,
            error: carrier_error(f.error),
        }
    })?;
    let (status, _) = watch::channel(Status::new());
    Ok(Setup {
        inner: Box::pin(setup),
        config,
        status,
        done: false,
    })
}
fn carrier_error(error: carrier::Error) -> io::Error {
    let kind = match &error {
        carrier::Error::Io { kind, .. } => *kind,
        carrier::Error::Expired
        | carrier::Error::Pair(l2tunnel_raw_io::handoff::pairing::PairError::Expired) => {
            io::ErrorKind::TimedOut
        }
        carrier::Error::Busy => io::ErrorKind::WouldBlock,
        carrier::Error::Pair(l2tunnel_raw_io::handoff::pairing::PairError::Driver {
            kind, ..
        }) => *kind,
        _ => io::ErrorKind::InvalidData,
    };
    match error {
        carrier::Error::Io {
            raw_os_error: Some(errno),
            ..
        }
        | carrier::Error::Pair(l2tunnel_raw_io::handoff::pairing::PairError::Driver {
            raw_os_error: Some(errno),
            ..
        }) => io::Error::from_raw_os_error(errno),
        _ => io::Error::new(kind, error),
    }
}
fn increment(n: &mut u64) -> io::Result<()> {
    *n = n
        .checked_add(1)
        .ok_or_else(|| invalid("raw runtime exact counter exhausted"))?;
    Ok(())
}
fn ticks(now: Duration) -> io::Result<u64> {
    u64::try_from(now.as_nanos()).map_err(|_| invalid("raw runtime time exhausted"))
}
fn lane_id(index: usize) -> PairLane {
    if index == 0 {
        PairLane::First
    } else {
        PairLane::Second
    }
}
fn encode(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[1, kind, 0, 0]);
    out.extend_from_slice(body);
    out
}
fn decode(bytes: &[u8]) -> io::Result<(u8, &[u8])> {
    if bytes.len() < HEADER
        || bytes[..4] != *MAGIC
        || bytes[4] != 1
        || bytes[6..8] != [0; 2]
        || !(1..=3).contains(&bytes[5])
    {
        return Err(invalid("raw runtime record envelope"));
    }
    Ok((bytes[5], &bytes[HEADER..]))
}

struct Lane {
    engine: udp::Engine,
    fragmenter: Fragmenter,
    reassembly: Reassembler,
    fragments: VecDeque<Vec<u8>>,
    native: VecDeque<Vec<u8>>,
    pending: Option<(carrier::RecordKind, Vec<u8>)>,
    pending_data: Option<Vec<u8>>,
    sends: bool,
    receives: bool,
    credit_due: Instant,
    prefer_credit: bool,
}
struct Owner<I: PacketIo + Send + 'static, D: PacketDevice<Error = io::Error>> {
    carrier: PacketCarrier<I>,
    device: D,
    config: Config,
    pipeline: Pipeline,
    codec: FrameCodec,
    lanes: Vec<Lane>,
    ingress: Option<Vec<u8>>,
    selected: Option<pipeline::Packet>,
    packet: Vec<u8>,
    source: Vec<u8>,
    record: Vec<u8>,
    encoded: Vec<u8>,
    started: Instant,
    timer: Interval,
    status: Status,
    publisher: watch::Sender<Status>,
    cursor: usize,
}
impl<I: PacketIo + Send + 'static, D: PacketDevice<Error = io::Error>> Drop for Owner<I, D> {
    fn drop(&mut self) {
        self.status.phase = Phase::Stopped;
        self.publisher.send_replace(self.status.clone());
    }
}
impl<I: PacketIo + Send + 'static, D: PacketDevice<Error = io::Error>> Owner<I, D> {
    fn new(
        device: D,
        carrier: PacketCarrier<I>,
        config: Config,
        publisher: watch::Sender<Status>,
    ) -> io::Result<Self> {
        config.validate()?;
        if device.layer() != config.runtime.layer {
            return Err(invalid("raw native layer differs from authentication"));
        }
        let info = carrier.info();
        if info.duplex != config.duplex
            || carrier.max_record_bytes()
                != config
                    .transport
                    .packet
                    .max_record_bytes()
                    .map_err(carrier_error)?
        {
            return Err(invalid("raw runtime carrier policy differs"));
        }
        let count = if config.duplex == Duplex::Full { 1 } else { 2 };
        let codec = config.runtime.codec()?;
        let maximum = codec
            .max_encoded_len()
            .checked_add(4)
            .ok_or_else(|| invalid("raw native envelope length"))?;
        let chunk = config.arq.max_source_bytes - FRAGMENT_HEADER_BYTES;
        let max_fragments = u16::try_from(maximum.div_ceil(chunk))
            .map_err(|_| invalid("raw native fragment count"))?;
        let started = Instant::now();
        let mut lanes = Vec::with_capacity(count);
        for index in 0..count {
            let session = info.lanes[index]
                .ok_or_else(|| invalid("raw runtime actual lane missing"))?
                .session_id;
            let context = RecoveryContext {
                session: u128::from_be_bytes(session),
                epoch: 1,
                role: if info.is_client {
                    EndpointRole::Initiator
                } else {
                    EndpointRole::Responder
                },
            };
            let fragment_context = FragmentContext {
                session: SessionId(u64::from_be_bytes(
                    session[..8]
                        .try_into()
                        .map_err(|_| invalid("raw session length"))?,
                )),
                epoch: Epoch(1),
            };
            let sends = config.duplex == Duplex::Full || (index == 0) == info.is_client;
            lanes.push(Lane {
                engine: udp::Engine::from_policy(config.policy()?, context)?,
                fragmenter: Fragmenter::new(
                    fragment_context,
                    FragmentConfig {
                        path_mtu: config.arq.max_source_bytes,
                        outer_overhead_bytes: 0,
                        max_message_bytes: maximum,
                        max_fragments,
                    },
                    MessageId(0),
                )
                .map_err(io::Error::other)?,
                reassembly: Reassembler::new(
                    fragment_context,
                    ReassemblyConfig {
                        max_message_bytes: maximum,
                        max_messages: 1,
                        max_fragment_payload_bytes: u16::try_from(chunk)
                            .map_err(|_| invalid("raw fragment chunk"))?,
                        max_fragments_per_message: max_fragments,
                        max_total_fragments: usize::from(max_fragments),
                        max_reserved_bytes: maximum,
                        max_lifetime_ticks: ticks(config.reassembly_timeout)?,
                        replay_window: 64,
                    },
                )
                .map_err(io::Error::other)?,
                fragments: VecDeque::with_capacity(usize::from(max_fragments)),
                native: VecDeque::with_capacity(config.runtime.queue_packets),
                pending: None,
                pending_data: None,
                sends,
                receives: config.duplex == Duplex::Full || !sends,
                credit_due: started,
                prefer_credit: true,
            });
        }
        let mut timer = tokio::time::interval(config.runtime.poll_interval);
        timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut status = Status::new();
        status.phase = Phase::Active;
        publisher.send_replace(status.clone());
        Ok(Self {
            carrier,
            device,
            config,
            pipeline: Pipeline::new(config.pipeline).map_err(io::Error::other)?,
            codec,
            lanes,
            ingress: None,
            selected: None,
            packet: vec![0; l2tunnel_device::READ_BUFFER_BYTES],
            source: vec![0; config.arq.max_source_bytes],
            record: vec![0; maximum],
            encoded: vec![0; config.recovery_bytes()?],
            started,
            timer,
            status,
            publisher,
            cursor: 0,
        })
    }
    fn live(&mut self) -> io::Result<()> {
        self.carrier.check_live().map_err(carrier_error)
    }
    fn receive(&mut self, now: Duration) -> io::Result<bool> {
        let Some(record) = self.carrier.record() else {
            return Ok(false);
        };
        let index = if record.lane == PairLane::First { 0 } else { 1 };
        let (kind, body) = decode(&record.bytes)?;
        let lane = self
            .lanes
            .get_mut(index)
            .ok_or_else(|| invalid("raw runtime receive lane"))?;
        match (record.kind, kind) {
            (carrier::RecordKind::Data, 1) if lane.receives => {
                if lane
                    .engine
                    .inspect(body, self.config.arq.max_source_bytes)?
                    == RecoveryKind::Feedback
                {
                    return Err(invalid("raw feedback on user record path"));
                }
                match lane.engine.receive(body, now) {
                    Ok(()) => {}
                    Err(e) if udp::pressure(&e, BufferSide::Receive) => {}
                    Err(e) => return Err(e),
                }
            }
            (carrier::RecordKind::Feedback, 2) => {
                if lane
                    .engine
                    .inspect(body, self.config.arq.max_source_bytes)?
                    != RecoveryKind::Feedback
                {
                    return Err(invalid("raw data on session feedback path"));
                }
                lane.engine.receive(body, now)?;
            }
            (carrier::RecordKind::Feedback, 3) if body.len() == 8 => {
                let value =
                    u64::from_be_bytes(body.try_into().map_err(|_| invalid("raw credit length"))?);
                if value > self.status.admitted[index] {
                    return Err(invalid("raw native credit exceeds admission"));
                }
                // This is an unordered protected carrier: a delayed cumulative
                // value is idempotent and cannot release any new native credit.
                self.status.peer_delivered[index] = self.status.peer_delivered[index].max(value);
            }
            _ => {
                return Err(invalid(
                    "raw runtime control/data kind or direction mismatch",
                ));
            }
        }
        self.carrier.consume_record().map_err(carrier_error)?;
        Ok(true)
    }
    fn native(&mut self, index: usize, now: Duration) -> io::Result<bool> {
        let mut progress = false;
        if !self.lanes[index]
            .reassembly
            .expire(ticks(now)?)
            .map_err(io::Error::other)?
            .is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "raw native reassembly expired",
            ));
        }
        if let Some(packet) = self.lanes[index].native.front() {
            let next = self.status.delivered[index]
                .checked_add(1)
                .ok_or_else(|| invalid("raw native delivered counter exhausted"))?;
            match self.device.transmit(packet) {
                Ok(()) => {
                    self.lanes[index].native.pop_front();
                    self.status.delivered[index] = next;
                    self.lanes[index].credit_due = Instant::now();
                    progress = true;
                    self.live()?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.live()?;
                }
                Err(e) => return Err(e),
            }
        }
        if self.lanes[index].native.len() < self.config.runtime.queue_packets
            && let Some((_, length)) = self.lanes[index].engine.delivered(&mut self.source)?
        {
            progress = true;
            if let ReassemblyStatus::Complete { message, length } = self.lanes[index]
                .reassembly
                .accept(&self.source[..length], ticks(now)?, &mut self.record)
                .map_err(io::Error::other)?
            {
                if message.0 != self.status.received[index]
                    || self.status.received[index]
                        .checked_sub(self.status.delivered[index])
                        .ok_or_else(|| invalid("raw received/delivered invariant"))?
                        >= self.config.runtime.queue_packets as u64
                    || length < 4
                    || self.record[2..4] != [0; 2]
                    || (self.config.runtime.compression == Compression::None
                        && self.record.get(8) != Some(&0))
                {
                    return Err(invalid("raw native frame sequence/window/envelope"));
                }
                let channel = u16::from_be_bytes([self.record[0], self.record[1]]);
                let packet = self
                    .codec
                    .decode_vec(&self.record[4..length])
                    .map_err(io::Error::other)?;
                if channel >= self.config.pipeline.flows.channels
                    || !packet_valid(self.config.runtime.layer, &packet)
                {
                    return Err(invalid("raw native channel or layer mismatch"));
                }
                let classification = self.pipeline.classify(&packet).map_err(io::Error::other)?;
                self.pipeline
                    .learn(classification.key, channel, 1, now)
                    .map_err(io::Error::other)?;
                self.lanes[index].native.push_back(packet);
                increment(&mut self.status.received[index])?;
            }
        }
        Ok(progress)
    }
    fn ingress(&mut self, now: Duration) -> io::Result<bool> {
        let mut progress = false;
        if self.ingress.is_none()
            && self.pipeline.usage().packets < self.config.pipeline.queue.packets
        {
            let received = self.device.receive(&mut self.packet)?;
            self.live()?;
            if let Some(length) = received {
                if length > self.config.runtime.max_packet
                    || length > self.packet.len()
                    || !packet_valid(self.config.runtime.layer, &self.packet[..length])
                {
                    return Err(invalid("raw native input length/layer"));
                }
                self.ingress = Some(self.packet[..length].to_vec());
                progress = true;
            }
        }
        if let Some(bytes) = self.ingress.take() {
            match self.pipeline.enqueue(bytes, now) {
                Ok(_) => progress = true,
                Err(e) if matches!(e.kind, pipeline::PipelineError::Budget(_)) => {
                    self.ingress = Some(e.payload)
                }
                Err(e) => return Err(io::Error::other(e)),
            }
        }
        Ok(progress)
    }
    fn admit(&mut self, index: usize, now: Duration) -> io::Result<bool> {
        if !self.lanes[index].sends {
            return Ok(false);
        }
        let mut progress = false;
        if self.lanes[index].fragments.is_empty()
            && self.status.admitted[index]
                .checked_sub(self.status.peer_delivered[index])
                .ok_or_else(|| invalid("raw admitted/confirmed invariant"))?
                < self.config.runtime.queue_packets as u64
        {
            if self.selected.is_none() {
                self.selected = self.pipeline.dequeue().map_err(io::Error::other)?;
            }
            if let Some(packet) = self.selected.take() {
                let next = self.status.admitted[index]
                    .checked_add(1)
                    .ok_or_else(|| invalid("raw admission counter exhausted"))?;
                let encoded = self
                    .codec
                    .encode_vec(&packet.payload)
                    .map_err(io::Error::other)?;
                let mut record = Vec::with_capacity(encoded.len() + 4);
                record.extend_from_slice(&packet.metadata.binding.channel.to_be_bytes());
                record.extend_from_slice(&[0; 2]);
                record.extend_from_slice(&encoded);
                self.lanes[index].fragments = self.lanes[index]
                    .fragmenter
                    .fragment(&record)
                    .map_err(io::Error::other)?
                    .fragments
                    .into();
                self.status.admitted[index] = next;
                progress = true;
            }
        }
        for _ in 0..8 {
            let lane = &mut self.lanes[index];
            let Some(fragment) = lane.fragments.front() else {
                break;
            };
            let next = self.status.sources[index]
                .checked_add(1)
                .ok_or_else(|| invalid("raw source counter exhausted"))?;
            match lane.engine.submit(fragment, now) {
                Ok(_) => {
                    self.lanes[index].fragments.pop_front();
                    self.status.sources[index] = next;
                    progress = true;
                }
                Err(e) if udp::pressure(&e, BufferSide::Send) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(progress)
    }
    fn output(&mut self, index: usize, now: Duration) -> io::Result<bool> {
        let mut progress = false;
        if self.lanes[index].pending.is_none() {
            // One bounded recovery feedback emission precedes new data. Native
            // confirmation also has periodic finite service even when user data
            // is blocked; both enter the same protected carrier allowance.
            let due = Instant::now() >= self.lanes[index].credit_due;
            let credit_first = due && self.lanes[index].prefer_credit;
            self.lanes[index].prefer_credit = !self.lanes[index].prefer_credit;
            let mut allowance = OutboundBudget {
                packets: 1,
                wire_bytes: self.encoded.len(),
            };
            if credit_first {
                self.lanes[index].pending = Some((
                    carrier::RecordKind::Feedback,
                    encode(3, &self.status.delivered[index].to_be_bytes()),
                ));
                self.lanes[index].credit_due = Instant::now() + self.config.credit_interval;
            } else if let Some(length) =
                self.lanes[index]
                    .engine
                    .poll(true, now, &mut self.encoded, &mut allowance)?
            {
                self.lanes[index].pending = Some((
                    carrier::RecordKind::Feedback,
                    encode(2, &self.encoded[..length]),
                ));
            } else if due && !self.lanes[index].sends {
                self.lanes[index].pending = Some((
                    carrier::RecordKind::Feedback,
                    encode(3, &self.status.delivered[index].to_be_bytes()),
                ));
                self.lanes[index].credit_due = Instant::now() + self.config.credit_interval;
            }
        }
        if let Some((kind, bytes)) = &self.lanes[index].pending {
            match self.carrier.stage_record(lane_id(index), *kind, bytes) {
                Ok(()) => {
                    self.lanes[index].pending = None;
                    increment(&mut self.status.staged[index])?;
                    progress = true;
                }
                Err(carrier::Error::Busy) => {}
                Err(e) => return Err(carrier_error(e)),
            }
        }
        if self.lanes[index].pending_data.is_none() && self.lanes[index].sends {
            let mut allowance = OutboundBudget {
                packets: 1,
                wire_bytes: self.encoded.len(),
            };
            if let Some(length) =
                self.lanes[index]
                    .engine
                    .poll(false, now, &mut self.encoded, &mut allowance)?
            {
                self.lanes[index].pending_data = Some(encode(1, &self.encoded[..length]));
            }
        }
        if self.lanes[index].pending.is_none()
            && let Some(bytes) = &self.lanes[index].pending_data
        {
            match self
                .carrier
                .stage_record(lane_id(index), carrier::RecordKind::Data, bytes)
            {
                Ok(()) => {
                    self.lanes[index].pending_data = None;
                    increment(&mut self.status.staged[index])?;
                    progress = true;
                }
                Err(carrier::Error::Busy) => {}
                Err(e) => return Err(carrier_error(e)),
            }
        }
        Ok(progress)
    }
    fn turn(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        self.live()?;
        let mut progress = false;
        if let Poll::Ready(result) = self.carrier.poll_progress(cx) {
            result.map_err(carrier_error)?;
            progress = true;
        }
        self.live()?;
        let now = self.started.elapsed();
        for _ in 0..8 {
            if !self.receive(now)? {
                break;
            }
            progress = true;
            self.live()?;
        }
        for offset in 0..self.lanes.len() {
            let index = (self.cursor + offset) % self.lanes.len();
            progress |= self.native(index, now)?;
            self.live()?;
        }
        progress |= self.ingress(now)?;
        for offset in 0..self.lanes.len() {
            let index = (self.cursor + offset) % self.lanes.len();
            progress |= self.admit(index, now)?;
            progress |= self.output(index, now)?;
            self.live()?;
        }
        self.cursor = (self.cursor + 1) % self.lanes.len();
        self.publisher.send_if_modified(|old| {
            if old != &self.status {
                *old = self.status.clone();
                true
            } else {
                false
            }
        });
        if Pin::new(&mut self.timer).poll_tick(cx).is_ready() {
            progress = true;
        }
        Ok(progress)
    }
}
/// Forward real native frames through the authenticated common-MUX/recovery path.
/// Cancellation or any error drops the exact original I/O without clean-close claims.
pub async fn run<I: PacketIo + Send + 'static, D: PacketDevice<Error = io::Error>>(
    device: D,
    mut link: Link<I>,
) -> io::Result<()> {
    let carrier = link
        .carrier
        .take()
        .ok_or_else(|| invalid("raw runtime link already consumed"))?;
    let mut owner = match Owner::new(device, carrier, link.config, link.status.clone()) {
        Ok(owner) => owner,
        Err(e) => {
            link.status.send_modify(|s| {
                s.phase = Phase::Stopped;
                s.fault = Some(e.kind());
            });
            return Err(e);
        }
    };
    // Link's Drop must not overwrite the active observation when it relinquishes
    // its carrier. Retain its bounded publisher until the whole run future ends.
    std::future::poll_fn(|cx| match owner.turn(cx) {
        Ok(progress) => {
            if progress {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
        Err(e) => {
            owner.status.fault = Some(e.kind());
            Poll::Ready(Err(e))
        }
    })
    .await
}

#[cfg(test)]
mod tests;

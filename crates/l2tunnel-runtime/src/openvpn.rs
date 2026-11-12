//! Fixed system-FIFO packet devices over standalone OpenVPN-like UDP.
//! The carrier owns recovery and pacing; this adapter only frames native packets.
/// Additive authenticated native prefix drain; legacy run remains unchanged.
pub mod drain;

use super::{Compression, Duplex, RuntimeConfig, invalid, packet_valid};
use l2tunnel_auth::{SessionConfig, SessionInfo};
use l2tunnel_codec::{
    FRAGMENT_HEADER_BYTES, FragmentConfig, FragmentContext, Fragmenter, MessageId, Reassembler,
    ReassemblyConfig, ReassemblyStatus, SessionId,
};
use l2tunnel_core::{ConfigDigest, Epoch};
use l2tunnel_device::PacketDevice;
use l2tunnel_openvpn as carrier;
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::{Instant, MissedTickBehavior, interval, timeout_at},
};

/// Complete bounded native policy, bound before carrier authentication.
#[derive(Clone, Copy, Debug)]
pub struct DeviceConfig {
    /// Packet layer, ceiling, stateless compression, output queue and polling.
    pub native: RuntimeConfig,
    /// One full lane or two authenticated complementary bulk lanes.
    pub duplex: Duplex,
    /// Fixed maximum lifetime after the first fragment arrives.
    pub reassembly_timeout: Duration,
    /// Maximum native transmit operations in one actor iteration.
    pub work_limit: usize,
    /// One absolute allowance for aborting and joining tasks after the first error.
    pub task_shutdown_timeout: Duration,
}
impl DeviceConfig {
    /// Validate all allocation/work/timer bounds before reading native input.
    pub fn validate(self) -> io::Result<()> {
        self.native.validate()?;
        if self
            .native
            .queue_packets
            .checked_mul(self.native.max_packet)
            .is_none_or(|v| v > 64 * 1024 * 1024)
            || self.reassembly_timeout.is_zero()
            || self.reassembly_timeout > Duration::from_secs(120)
            || !(1..=1024).contains(&self.work_limit)
            || self.task_shutdown_timeout.is_zero()
            || self.task_shutdown_timeout > Duration::from_secs(30)
        {
            return Err(invalid("standalone native queue/work/time bound"));
        }
        for value in [
            self.native.poll_interval,
            self.reassembly_timeout,
            self.task_shutdown_timeout,
        ] {
            micros(value)?;
        }
        Ok(())
    }
    /// Canonical native base supplied to the actual standalone carrier factories.
    pub fn base_session_config(self) -> io::Result<SessionConfig> {
        self.validate()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/openvpn-device/v1/frame-v1/fragment-v1/system-fifo-one-channel\0");
        hash.update(&[
            match self.native.layer {
                l2tunnel_device::PacketLayer::Ethernet => 1,
                l2tunnel_device::PacketLayer::Ip => 2,
            },
            match self.native.compression {
                Compression::None => 0,
                Compression::Lz4IfSmaller => 1,
            },
            match self.duplex {
                Duplex::Full => 1,
                Duplex::Half => 2,
            },
        ]);
        for value in [
            self.native.max_packet as u64,
            self.native.queue_packets as u64,
            micros(self.native.poll_interval)?,
            micros(self.reassembly_timeout)?,
            self.work_limit as u64,
            micros(self.task_shutdown_timeout)?,
            256,
            1,
            64,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(hash.finish().as_ref());
        Ok(SessionConfig {
            layer: self.native.layer,
            digest: ConfigDigest(digest),
        })
    }
}
fn micros(value: Duration) -> io::Result<u64> {
    if !value.subsec_nanos().is_multiple_of(1000) {
        return Err(invalid("native sub-microsecond timeout"));
    }
    u64::try_from(value.as_micros()).map_err(|_| invalid("native timeout overflow"))
}
fn ticks(value: Duration) -> io::Result<u64> {
    u64::try_from(value.as_micros()).map_err(|_| invalid("native monotonic ticks exhausted"))
}
/// Local ownership and actual native handoff counters, not remote credit claims.
///
/// Retention and TLS-progress fields describe the last completed actor iteration.
/// They can lag an error or cancellation even when `stopped` is true; they are not
/// an exact final inventory. Event counters advance at the documented handoff.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Whole packets accepted from the device.
    pub native_ingress: u64,
    /// Source fragments whose carrier admission returned success to this adapter.
    pub sources_admitted: u64,
    /// Recovered carrier source records handed to this adapter.
    pub sources_received: u64,
    /// Complete packets successfully transmitted by the native device.
    pub native_delivered: u64,
    /// Outbound source fragments still retained, including the writer handoff.
    pub outbound_fragments: usize,
    /// Retained outbound source bytes including all fragment headers.
    pub outbound_bytes: usize,
    /// Incomplete native records currently reserved.
    pub reassembly_messages: usize,
    /// Exact reassembly reservation, separate from fixed scratch buffers.
    pub reassembly_bytes: usize,
    /// Complete native packets awaiting actual device transmit.
    pub native_queue_packets: usize,
    /// Original native bytes awaiting device transmit.
    pub native_queue_bytes: usize,
    /// Actual fresh internal TLS messages across owned physical lanes.
    pub tls_messages: u64,
    /// Runtime ended or was cancelled; never a clean native-shutdown receipt.
    pub stopped: bool,
}
/// Read-only bounded snapshot handle; it carries no packet or authentication authority.
#[derive(Clone)]
pub struct Observer(Arc<Mutex<Snapshot>>);
impl Observer {
    /// Copy local counters without consuming packet ownership.
    pub fn snapshot(&self) -> io::Result<Snapshot> {
        self.change(|s| Ok(*s))
    }
    fn change<T>(&self, action: impl FnOnce(&mut Snapshot) -> io::Result<T>) -> io::Result<T> {
        let mut value = self
            .0
            .lock()
            .map_err(|_| invalid("native observer poisoned"))?;
        action(&mut value)
    }
}
enum Owner {
    Full(carrier::Control),
    Paired(carrier::PairControl),
}
impl Owner {
    fn health(&self) -> io::Result<u64> {
        match self {
            Self::Full(value) => carrier_health(&[value.status().map_err(carrier_error)?]),
            Self::Paired(value) => carrier_health(&value.status().map_err(carrier_error)?.lanes),
        }
    }
}
fn carrier_health(lanes: &[carrier::Status]) -> io::Result<u64> {
    if lanes.iter().any(|s| s.terminal.is_some() || s.closing) {
        let kind = if lanes
            .iter()
            .any(|s| s.terminal == Some(carrier::Terminal::Timeout))
        {
            io::ErrorKind::TimedOut
        } else {
            io::ErrorKind::UnexpectedEof
        };
        // Timeout identifies an actual carrier terminal enum. It does not
        // distinguish inactivity, lease expiry or another finite deadline.
        let mut message = Diagnostic(String::with_capacity(DIAGNOSTIC_BYTES));
        let _ = std::fmt::write(
            &mut message,
            format_args!("carrier ended before distributed native drain; incomplete; "),
        );
        for (index, lane) in lanes.iter().enumerate() {
            let _ = std::fmt::write(
                &mut message,
                format_args!(
                    "lane {index} terminal={:?} closing={}; ",
                    lane.terminal, lane.closing
                ),
            );
        }
        return Err(io::Error::new(kind, message.0));
    }
    lanes.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(value.tls_messages)
            .ok_or_else(|| invalid("TLS observation count"))
    })
}
const DIAGNOSTIC_BYTES: usize = 512;
struct Diagnostic(String);
impl std::fmt::Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let mut length = value
            .len()
            .min(DIAGNOSTIC_BYTES.saturating_sub(self.0.len()));
        while !value.is_char_boundary(length) {
            length -= 1;
        }
        self.0.push_str(&value[..length]);
        Ok(())
    }
}
fn diagnostic(value: std::fmt::Arguments<'_>) -> String {
    let mut output = Diagnostic(String::with_capacity(DIAGNOSTIC_BYTES));
    let _ = std::fmt::write(&mut output, value);
    output.0
}
fn copy_error(error: &io::Error) -> io::Error {
    match error.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(error.kind(), diagnostic(format_args!("{error}"))),
    }
}
fn carrier_error(error: carrier::Error) -> io::Error {
    match error {
        carrier::Error::Io(value) => copy_error(&value),
        carrier::Error::Timeout => io::Error::new(
            io::ErrorKind::TimedOut,
            "carrier Timeout; deadline cause not distinguished",
        ),
        carrier::Error::Closed => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "carrier Closed; native drain incomplete",
        ),
        carrier::Error::IncompleteClose => io::Error::new(
            io::ErrorKind::TimedOut,
            "carrier IncompleteClose; native drain incomplete",
        ),
        value => io::Error::other(diagnostic(format_args!("{value}"))),
    }
}
fn source_ended() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "native source stream ended without a reported terminal cause",
    )
}
fn relay_source(
    result: io::Result<usize>,
    buffer: &[u8],
    permit: mpsc::Permit<'_, io::Result<Vec<u8>>>,
) -> io::Result<()> {
    match result.and_then(|length| {
        buffer
            .get(..length)
            .ok_or_else(|| invalid("carrier source length"))
    }) {
        Ok(bytes) => {
            permit.send(Ok(bytes.to_vec()));
            Ok(())
        }
        Err(error) => {
            let error = copy_error(&error);
            // The slot is reserved before receive. Publish the same bounded
            // cause before task completion can drop the channel sender.
            permit.send(Err(copy_error(&error)));
            Err(error)
        }
    }
}
/// Actual verified carrier capability bound to one exact native configuration.
pub struct Link {
    owner: Owner,
    sender: carrier::PacketSender,
    receiver: carrier::PacketReceiver,
    binding: SessionConfig,
    send_session: [u8; 16],
    receive_session: [u8; 16],
    send_source: usize,
    receive_source: usize,
    observer: Observer,
}
impl Link {
    /// Bind a genuine full carrier; caller-supplied session metadata is insufficient.
    pub fn full(
        carrier: carrier::Carrier,
        transport: carrier::Config,
        config: DeviceConfig,
    ) -> io::Result<Self> {
        if config.duplex != Duplex::Full
            || transport.profile.traffic != carrier::Traffic::FullDuplex
        {
            return Err(invalid("standalone full/native mode mismatch"));
        }
        verify(*carrier.info(), transport, config)?;
        let info = *carrier.info();
        let (owner, sender, receiver) = carrier.split();
        Ok(Self {
            owner: Owner::Full(owner),
            sender,
            receiver,
            binding: config.base_session_config()?,
            send_session: info.session_id,
            receive_session: info.session_id,
            send_source: transport.arq.max_source_bytes,
            receive_source: transport.arq.max_source_bytes,
            observer: Observer(Arc::new(Mutex::new(Snapshot::default()))),
        })
    }
    /// Bind the actual exporter-joined pair in canonical bulk-direction order.
    pub fn paired(
        carrier: carrier::PairedCarrier,
        transports: [carrier::Config; 2],
        config: DeviceConfig,
    ) -> io::Result<Self> {
        if config.duplex != Duplex::Half {
            return Err(invalid("standalone pair/native mode mismatch"));
        }
        let info = *carrier.info();
        for (lane, transport) in info.lanes.into_iter().zip(transports) {
            verify(lane, transport, config)?;
        }
        let server = info.lanes[0].peer_member.is_some();
        let send = usize::from(server);
        let receive = 1 - send;
        let (owner, sender, receiver) = carrier.split();
        Ok(Self {
            owner: Owner::Paired(owner),
            sender,
            receiver,
            binding: config.base_session_config()?,
            send_session: info.lanes[send].session_id,
            receive_session: info.lanes[receive].session_id,
            send_source: transports[send].arq.max_source_bytes,
            receive_source: transports[receive].arq.max_source_bytes,
            observer: Observer(Arc::new(Mutex::new(Snapshot::default()))),
        })
    }
    /// Observe actual local ownership and native delivery while `run` owns the link.
    pub fn observer(&self) -> Observer {
        self.observer.clone()
    }
}
fn verify(info: SessionInfo, transport: carrier::Config, config: DeviceConfig) -> io::Result<()> {
    if transport.base != config.base_session_config()?
        || info.config != transport.session_config().map_err(io::Error::other)?
    {
        return Err(invalid("standalone actual carrier/native binding mismatch"));
    }
    geometry(config, transport.arq.max_source_bytes)?;
    Ok(())
}
fn geometry(config: DeviceConfig, source: usize) -> io::Result<(usize, u16)> {
    config.validate()?;
    let maximum = config.native.codec()?.max_encoded_len();
    let chunk = source
        .checked_sub(FRAGMENT_HEADER_BYTES)
        .filter(|v| *v > 0 && *v <= usize::from(u16::MAX))
        .ok_or_else(|| invalid("standalone fragment source bound"))?;
    let fragments = maximum.div_ceil(chunk);
    if fragments > 256 {
        return Err(invalid("standalone fragment count bound"));
    }
    Ok((
        chunk,
        u16::try_from(fragments).map_err(|_| invalid("fragment count"))?,
    ))
}
fn context(session: [u8; 16]) -> io::Result<FragmentContext> {
    // This truncated value is only a local framing discriminator. The enclosing
    // carrier authenticates the full 128-bit session, direction and exact profile.
    Ok(FragmentContext {
        session: SessionId(u64::from_be_bytes(
            session[..8]
                .try_into()
                .map_err(|_| invalid("session context"))?,
        )),
        epoch: Epoch(1),
    })
}
fn increment(value: &mut u64) -> io::Result<()> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| invalid("native counter exhausted"))?;
    Ok(())
}
struct Job {
    bytes: Vec<u8>,
    admitted: oneshot::Sender<io::Result<()>>,
}
struct Stopped(Observer);
impl Drop for Stopped {
    fn drop(&mut self) {
        let _ = self.0.change(|s| {
            s.stopped = true;
            Ok(())
        });
    }
}

/// Long-lived system-FIFO forwarding; errors/cancellation are not clean native close.
/// The adapter never adds a second recovery engine or wire allowance.
pub async fn run<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    link: Link,
    config: DeviceConfig,
) -> io::Result<()> {
    let _stopped = Stopped(link.observer.clone());
    if device.layer() != config.native.layer || link.binding != config.base_session_config()? {
        return Err(invalid("standalone device/runtime binding mismatch"));
    }
    let Link {
        owner,
        sender,
        mut receiver,
        send_session,
        receive_session,
        send_source,
        receive_source,
        observer,
        ..
    } = link;
    let mut tasks = JoinSet::new();
    let (outbound, mut jobs) = mpsc::channel::<Job>(1);
    let (incoming, mut sources) = mpsc::channel::<io::Result<Vec<u8>>>(1);
    let counts = observer.clone();
    tasks.spawn(async move {
        while let Some(job) = jobs.recv().await {
            match sender.send(&job.bytes).await {
                Ok(()) => {
                    counts.change(|s| increment(&mut s.sources_admitted))?;
                    let _ = job.admitted.send(Ok(()));
                }
                Err(error) => {
                    let error = carrier_error(error);
                    let _ = job.admitted.send(Err(copy_error(&error)));
                    return Err(error);
                }
            }
        }
        Err(invalid("native writer ended without distributed drain"))
    });
    tasks.spawn(async move {
        let mut buffer = vec![0; receive_source];
        loop {
            let permit = incoming
                .reserve()
                .await
                .map_err(|_| invalid("native source handoff closed"))?;
            let result = receiver.receive(&mut buffer).await.map_err(carrier_error);
            relay_source(result, &buffer, permit)?;
        }
    });
    let result = pump(
        &mut device,
        &owner,
        &observer,
        &mut tasks,
        outbound,
        &mut sources,
        config,
        send_session,
        receive_session,
        send_source,
        receive_source,
    )
    .await;
    let deadline = Instant::now()
        .checked_add(config.task_shutdown_timeout)
        .ok_or_else(|| invalid("task shutdown deadline"))?;
    tasks.abort_all();
    timeout_at(deadline, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native task shutdown incomplete"))?;
    result
}
#[allow(clippy::too_many_arguments)] // One owner threads exact bounded contexts, queues and task set into the loop.
async fn pump<D: PacketDevice<Error = io::Error>>(
    device: &mut D,
    owner: &Owner,
    observer: &Observer,
    tasks: &mut JoinSet<io::Result<()>>,
    outbound: mpsc::Sender<Job>,
    sources: &mut mpsc::Receiver<io::Result<Vec<u8>>>,
    config: DeviceConfig,
    send_session: [u8; 16],
    receive_session: [u8; 16],
    send_source: usize,
    receive_source: usize,
) -> io::Result<()> {
    let codec = config.native.codec()?;
    let maximum = codec.max_encoded_len();
    let (_, send_fragments) = geometry(config, send_source)?;
    let (receive_chunk, receive_fragments) = geometry(config, receive_source)?;
    let mut fragmenter = Fragmenter::new(
        context(send_session)?,
        FragmentConfig {
            path_mtu: send_source,
            outer_overhead_bytes: 0,
            max_message_bytes: maximum,
            max_fragments: send_fragments,
        },
        MessageId(0),
    )
    .map_err(io::Error::other)?;
    let mut reassembly = Reassembler::new(
        context(receive_session)?,
        ReassemblyConfig {
            max_message_bytes: maximum,
            max_messages: 1,
            max_fragment_payload_bytes: u16::try_from(receive_chunk)
                .map_err(|_| invalid("fragment chunk"))?,
            max_fragments_per_message: receive_fragments,
            max_total_fragments: usize::from(receive_fragments),
            max_reserved_bytes: maximum,
            max_lifetime_ticks: micros(config.reassembly_timeout)?,
            replay_window: 64,
        },
    )
    .map_err(io::Error::other)?;
    let mut packet = vec![0; l2tunnel_device::READ_BUFFER_BYTES];
    let mut record = vec![0; maximum];
    let mut fragments = VecDeque::<Vec<u8>>::new();
    let mut fragment_bytes = 0usize;
    let mut waiting = None::<oneshot::Receiver<io::Result<()>>>;
    let mut waiting_bytes = 0;
    let mut native = VecDeque::<Vec<u8>>::with_capacity(config.native.queue_packets);
    let mut native_bytes = 0usize;
    let mut expected = 0_u64;
    let started = Instant::now();
    let mut timer = interval(config.native.poll_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = tasks.join_next() => return match result { Some(Ok(Err(error))) => Err(error), Some(Err(error)) => Err(io::Error::other(error)), _ => Err(invalid("native task ended without drain")) },
            _ = timer.tick() => {},
            value = async { match &mut waiting { Some(value) => value.await, None => std::future::pending().await } } => { value.map_err(|_| invalid("native admission handoff ended"))??; waiting = None; waiting_bytes = 0; },
            value = sources.recv(), if native.len() < config.native.queue_packets => {
                let bytes = value.ok_or_else(source_ended)??;
                observer.change(|s| increment(&mut s.sources_received))?;
                if !reassembly.expire(ticks(started.elapsed())?).map_err(io::Error::other)?.is_empty() { return Err(io::Error::new(io::ErrorKind::TimedOut, "native reassembly expired")); }
                match reassembly.accept(&bytes, ticks(started.elapsed())?, &mut record).map_err(io::Error::other)? {
                    ReassemblyStatus::Pending { message, .. } if message.0 == expected => {},
                    ReassemblyStatus::Duplicate { message } if message.0 <= expected => {},
                    ReassemblyStatus::Complete { message, length } if message.0 == expected => {
                        if config.native.compression == Compression::None && record.get(4) != Some(&0) { return Err(invalid("native compression mismatch")); }
                        let value = codec.decode_vec(&record[..length]).map_err(io::Error::other)?;
                        if !packet_valid(config.native.layer, &value) { return Err(invalid("invalid decoded native packet")); }
                        native_bytes = native_bytes.checked_add(value.len()).ok_or_else(|| invalid("native queue bytes"))?; native.push_back(value); increment(&mut expected)?;
                    }
                    _ => return Err(invalid("native message sequence gap")),
                }
            }
        }
        let tls_messages = owner.health()?;
        if !reassembly
            .expire(ticks(started.elapsed())?)
            .map_err(io::Error::other)?
            .is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native reassembly expired",
            ));
        }
        for _ in 0..config.work_limit {
            let Some(value) = native.front() else {
                break;
            };
            match device.transmit(value) {
                Ok(()) => {
                    native_bytes -= value.len();
                    native.pop_front();
                    observer.change(|s| increment(&mut s.native_delivered))?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if fragments.is_empty()
            && waiting.is_none()
            && let Some(length) = device.receive(&mut packet)?
        {
            if length > config.native.max_packet
                || !packet_valid(config.native.layer, &packet[..length])
            {
                return Err(invalid("invalid or oversized native ingress"));
            }
            let encoded = codec
                .encode_vec(&packet[..length])
                .map_err(io::Error::other)?;
            let batch = fragmenter.fragment(&encoded).map_err(io::Error::other)?;
            fragment_bytes = batch
                .fragments
                .iter()
                .try_fold(0usize, |sum, part| sum.checked_add(part.len()))
                .ok_or_else(|| invalid("fragment batch bytes"))?;
            fragments = batch.fragments.into();
            observer.change(|s| increment(&mut s.native_ingress))?;
        }
        if waiting.is_none() && !fragments.is_empty() {
            let permit = outbound
                .try_reserve()
                .map_err(|_| invalid("one-source writer handoff invariant"))?;
            let bytes = fragments
                .pop_front()
                .ok_or_else(|| invalid("missing source"))?;
            waiting_bytes = bytes.len();
            fragment_bytes -= waiting_bytes;
            let (admitted, result) = oneshot::channel();
            permit.send(Job { bytes, admitted });
            waiting = Some(result);
        }
        observer.change(|s| {
            s.outbound_fragments = fragments.len() + usize::from(waiting.is_some());
            s.outbound_bytes = fragment_bytes + waiting_bytes;
            s.reassembly_messages = reassembly.pending_messages();
            s.reassembly_bytes = reassembly.reserved_bytes();
            s.native_queue_packets = native.len();
            s.native_queue_bytes = native_bytes;
            s.tls_messages = tls_messages;
            Ok(())
        })?;
    }
}

#[cfg(test)]
#[path = "openvpn_tests.rs"]
mod tests;

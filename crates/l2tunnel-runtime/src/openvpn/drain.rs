//! Distributed native prefix confirmation over the carrier's authenticated OVC2 owner.
//! One adapter actor retains the original receiver and one pinned source-send future.
use super::*;
use carrier::{NativeControlState, NativeFence};
use std::{future::Future, pin::Pin};

/// Additive native policy. Legacy DeviceConfig and run retain their existing profile.
#[derive(Clone, Copy, Debug)]
pub struct DrainConfig {
    /// Exact packet, codec, queue, reassembly and work limits.
    pub device: DeviceConfig,
    /// One original native-drain allowance, including carrier task shutdown.
    pub drain_timeout: Duration,
}
impl DrainConfig {
    /// Validate native bounds and the finite integral-microsecond drain duration.
    pub fn validate(self) -> io::Result<()> {
        self.device.validate()?;
        if !(Duration::from_millis(1)..=Duration::from_secs(120)).contains(&self.drain_timeout) {
            return Err(invalid("native drain duration"));
        }
        micros(self.drain_timeout)?;
        Ok(())
    }
    /// Canonical device base to supply before constructing NativeDrainConfig.
    pub fn base_session_config(self) -> io::Result<SessionConfig> {
        self.validate()?;
        let base = self.device.base_session_config()?;
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(b"l2tunnel/openvpn-native-device/v2/direct-actor\0");
        hash.update(&base.digest.0);
        hash.update(&micros(self.drain_timeout)?.to_be_bytes());
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.finish().as_ref());
        Ok(SessionConfig {
            layer: base.layer,
            digest: ConfigDigest(bytes),
        })
    }
}
/// One-use shutdown producer. Dropping it without request cancels the adapter.
pub struct ShutdownRequest(oneshot::Sender<Instant>);
/// Shutdown receiver; the producer records request time before sending it.
pub struct ShutdownSignal(oneshot::Receiver<Instant>);
/// Create a bounded one-use local stop request, without starting a deadline yet.
pub fn shutdown_request() -> (ShutdownRequest, ShutdownSignal) {
    let (tx, rx) = oneshot::channel();
    (ShutdownRequest(tx), ShutdownSignal(rx))
}
impl ShutdownRequest {
    /// Record monotonic request time and signal the actor. Failure means it ended.
    pub fn request(self) -> io::Result<()> {
        self.0
            .send(Instant::now())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "native drain actor ended"))
    }
}
enum NativeOwner {
    Full(carrier::NativeControl),
    Paired(carrier::NativePairControl),
}
impl NativeOwner {
    fn request(&self) -> io::Result<()> {
        match self {
            Self::Full(v) => v.request_stop(),
            Self::Paired(v) => v.request_stop(),
        }
        .map_err(carrier_error)
    }
    fn state(&self) -> io::Result<NativeControlState> {
        match self {
            Self::Full(v) => v.state(),
            Self::Paired(v) => v.state(),
        }
        .map_err(carrier_error)
    }
    async fn changed(&mut self) -> io::Result<NativeControlState> {
        match self {
            Self::Full(v) => v.changed().await,
            Self::Paired(v) => v.changed().await,
        }
        .map_err(carrier_error)
    }
    fn seal(&self) -> Result<carrier::SourceFence, carrier::Error> {
        match self {
            Self::Full(v) => v.seal_send(),
            Self::Paired(v) => v.seal_send(),
        }
    }
    fn publish(&self, f: NativeFence, s: &carrier::SourceFence) -> io::Result<()> {
        match self {
            Self::Full(v) => v.publish_fence(f.packets, f.native_bytes, s),
            Self::Paired(v) => v.publish_fence(f.packets, f.native_bytes, s),
        }
        .map_err(carrier_error)
    }
    fn ack(&self, f: &carrier::PeerFence) -> io::Result<()> {
        match self {
            Self::Full(v) => v.ack_peer_native(f),
            Self::Paired(v) => v.ack_peer_native(f),
        }
        .map_err(carrier_error)
    }
    async fn close(self) -> io::Result<CarrierClose> {
        match self {
            Self::Full(v) => Ok(CarrierClose::Full(v.close().await.map_err(carrier_error)?)),
            Self::Paired(v) => Ok(CarrierClose::Paired(
                v.close().await.map_err(carrier_error)?,
            )),
        }
    }
}
/// Actual verified native-profile capability bound to one exact device policy.
pub struct DrainingLink {
    owner: NativeOwner,
    sender: carrier::PacketSender,
    receiver: carrier::PacketReceiver,
    binding: SessionConfig,
    send_session: [u8; 16],
    receive_session: [u8; 16],
    send_source: usize,
    receive_source: usize,
}
impl DrainingLink {
    /// Bind a genuine full native capability; asserted session metadata is insufficient.
    pub fn full(
        value: carrier::NativeCarrier,
        transport: carrier::NativeDrainConfig,
        config: DrainConfig,
    ) -> io::Result<Self> {
        if config.device.duplex != Duplex::Full
            || transport.carrier().profile.traffic != carrier::Traffic::FullDuplex
        {
            return Err(invalid("native full mode mismatch"));
        }
        verify(*value.info(), transport, config)?;
        let info = *value.info();
        let (owner, sender, receiver) = value.split();
        Ok(Self {
            owner: NativeOwner::Full(owner),
            sender,
            receiver,
            binding: config.base_session_config()?,
            send_session: info.session_id,
            receive_session: info.session_id,
            send_source: transport.carrier().arq.max_source_bytes,
            receive_source: transport.carrier().arq.max_source_bytes,
        })
    }
    /// Bind actual joined complementary lanes in canonical bulk-direction order.
    pub fn paired(
        value: carrier::NativePairedCarrier,
        transports: [carrier::NativeDrainConfig; 2],
        config: DrainConfig,
    ) -> io::Result<Self> {
        if config.device.duplex != Duplex::Half {
            return Err(invalid("native paired mode mismatch"));
        }
        let info = *value.info();
        for (info, transport) in info.lanes.into_iter().zip(transports) {
            verify(info, transport, config)?;
        }
        let send = usize::from(info.lanes[0].peer_member.is_some());
        let receive = 1 - send;
        let (owner, sender, receiver) = value.split();
        Ok(Self {
            owner: NativeOwner::Paired(owner),
            sender,
            receiver,
            binding: config.base_session_config()?,
            send_session: info.lanes[send].session_id,
            receive_session: info.lanes[receive].session_id,
            send_source: transports[send].carrier().arq.max_source_bytes,
            receive_source: transports[receive].carrier().arq.max_source_bytes,
        })
    }
}
fn verify(
    info: SessionInfo,
    transport: carrier::NativeDrainConfig,
    config: DrainConfig,
) -> io::Result<()> {
    if transport.carrier().base != config.base_session_config()?
        || transport.drain_timeout() != config.drain_timeout
        || info.config != transport.session_config().map_err(carrier_error)?
    {
        return Err(invalid("actual native capability/config mismatch"));
    }
    geometry(config.device, transport.carrier().arq.max_source_bytes)?;
    Ok(())
}
/// Existing carrier clean receipts, produced only by the original supervised owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierClose {
    /// One full-duplex physical lane.
    Full(carrier::CloseReceipt),
    /// Client-to-server then server-to-client paired lanes.
    Paired([carrier::CloseReceipt; 2]),
}
/// Successful native prefix confirmation plus actual maintained carrier shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDrainReceipt {
    /// Exact local accepted native and admitted source prefix confirmed by the peer.
    pub local: NativeFence,
    /// Exact peer prefix delivered successfully to this native device.
    pub peer: NativeFence,
    /// Original earliest local/remote request deadline; all work completed before it.
    pub deadline: Instant,
    /// Actual carrier task and physical-output drain receipts.
    pub carrier: CarrierClose,
}
/// Authoritative actor inventory on an error, separate from carrier admission state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DrainProgress {
    /// Native accepted originals and source admissions returned to this actor.
    pub accepted: NativeFence,
    /// Complete sources copied into this actor's ownership.
    pub sources_received: u64,
    /// Bytes copied into this actor's ownership.
    pub source_bytes_received: u64,
    /// Whole originals decoded and validated.
    pub native_completed: u64,
    /// Original bytes decoded and validated.
    pub native_bytes_completed: u64,
    /// Whole originals accepted by PacketDevice::transmit.
    pub native_confirmed: u64,
    /// Bytes accepted by PacketDevice::transmit.
    pub native_bytes_confirmed: u64,
    /// Retained fragment count, including the one in-flight admission future.
    pub outbound_fragments: usize,
    /// Retained fragment bytes, including the one in-flight admission future.
    pub outbound_bytes: usize,
    /// True if a send may already be admitted but its result has not been observed.
    pub admission_in_flight: bool,
    /// Incomplete reassembly records.
    pub reassembly_messages: usize,
    /// Reserved incomplete reassembly bytes.
    pub reassembly_bytes: usize,
    /// Whole originals waiting for native transmit.
    pub pending_native_packets: usize,
    /// Bytes waiting for native transmit.
    pub pending_native_bytes: usize,
    /// Last observed authenticated control phase, not a terminal carrier inventory.
    pub control: Option<NativeControlState>,
}
/// Explicit non-clean result with bounded ownership evidence; never a clean receipt.
#[derive(Debug)]
pub struct NativeDrainError {
    /// Actual validation/I/O/timeout/cancellation reason, preserving OS errors.
    pub reason: io::Error,
    /// Exact local actor inventory at failure; an in-flight send is explicitly unknown.
    pub progress: DrainProgress,
}
impl std::fmt::Display for NativeDrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native drain incomplete: {}", self.reason)
    }
}
impl std::error::Error for NativeDrainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}
type Admission = Pin<Box<dyn Future<Output = Result<usize, carrier::Error>> + Send>>;
struct Actor {
    fragmenter: Fragmenter,
    reassembly: Reassembler,
    packet: Vec<u8>,
    record: Vec<u8>,
    source: Vec<u8>,
    fragments: VecDeque<Vec<u8>>,
    fragment_bytes: usize,
    admission: Option<Admission>,
    admission_bytes: usize,
    native: VecDeque<Vec<u8>>,
    native_bytes: usize,
    counts: DrainProgress,
    deadline: Option<Instant>,
    requested: bool,
}
impl Actor {
    fn new(link: &DrainingLink, config: DrainConfig) -> io::Result<Self> {
        let maximum = config.device.native.codec()?.max_encoded_len();
        let (_, send_count) = geometry(config.device, link.send_source)?;
        let (receive_chunk, receive_count) = geometry(config.device, link.receive_source)?;
        let fragmenter = Fragmenter::new(
            context(link.send_session)?,
            FragmentConfig {
                path_mtu: link.send_source,
                outer_overhead_bytes: 0,
                max_message_bytes: maximum,
                max_fragments: send_count,
            },
            MessageId(0),
        )
        .map_err(io::Error::other)?;
        let reassembly = Reassembler::new(
            context(link.receive_session)?,
            ReassemblyConfig {
                max_message_bytes: maximum,
                max_messages: 1,
                max_fragment_payload_bytes: u16::try_from(receive_chunk)
                    .map_err(|_| invalid("fragment chunk"))?,
                max_fragments_per_message: receive_count,
                max_total_fragments: usize::from(receive_count),
                max_reserved_bytes: maximum,
                max_lifetime_ticks: micros(config.device.reassembly_timeout)?,
                replay_window: 64,
            },
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            fragmenter,
            reassembly,
            packet: vec![0; l2tunnel_device::READ_BUFFER_BYTES],
            record: vec![0; maximum],
            source: vec![0; link.receive_source],
            fragments: VecDeque::new(),
            fragment_bytes: 0,
            admission: None,
            admission_bytes: 0,
            native: VecDeque::with_capacity(config.device.native.queue_packets),
            native_bytes: 0,
            counts: DrainProgress::default(),
            deadline: None,
            requested: false,
        })
    }
    fn snapshot(&self) -> DrainProgress {
        DrainProgress {
            outbound_fragments: self.fragments.len() + usize::from(self.admission.is_some()),
            outbound_bytes: self.fragment_bytes + self.admission_bytes,
            admission_in_flight: self.admission.is_some(),
            reassembly_messages: self.reassembly.pending_messages(),
            reassembly_bytes: self.reassembly.reserved_bytes(),
            pending_native_packets: self.native.len(),
            pending_native_bytes: self.native_bytes,
            ..self.counts
        }
    }
    fn shorten(&mut self, deadline: Instant) {
        self.deadline = Some(self.deadline.map_or(deadline, |old| old.min(deadline)));
    }
    fn expired(&self) -> io::Result<()> {
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original native drain deadline expired",
            ))
        } else {
            Ok(())
        }
    }
    fn compare_peer(&self, f: NativeFence) -> io::Result<bool> {
        for (actual, expected) in [
            (self.counts.sources_received, f.sources),
            (self.counts.source_bytes_received, f.source_bytes),
            (self.counts.native_completed, f.packets),
            (self.counts.native_bytes_completed, f.native_bytes),
            (self.counts.native_confirmed, f.packets),
            (self.counts.native_bytes_confirmed, f.native_bytes),
        ] {
            if actual > expected {
                return Err(invalid("native peer fence overshoot"));
            }
        }
        Ok(self.counts.sources_received == f.sources
            && self.counts.source_bytes_received == f.source_bytes
            && self.counts.native_completed == f.packets
            && self.counts.native_bytes_completed == f.native_bytes
            && self.counts.native_confirmed == f.packets
            && self.counts.native_bytes_confirmed == f.native_bytes
            && self.native.is_empty()
            && self.reassembly.pending_messages() == 0)
    }
}
fn add(value: &mut u64, amount: usize) -> io::Result<()> {
    *value = value
        .checked_add(amount as u64)
        .ok_or_else(|| invalid("native prefix exhausted"))?;
    Ok(())
}

/// Forward accepted originals, confirm peer delivery, then close within one deadline.
///
/// TAP uses the same system FIFO policy as legacy run. No endpoint TCP window or
/// extra ARQ state is introduced. Dropping this future cancels its original carrier
/// owners and produces no clean receipt. Unread device/kernel input is outside the
/// accepted prefix. The adapter spawns no tasks and never drops its receive owner
/// before the existing carrier close completes.
pub async fn run_draining<D: PacketDevice<Error = io::Error>>(
    mut device: D,
    mut link: DrainingLink,
    config: DrainConfig,
    mut stop: ShutdownSignal,
) -> Result<NativeDrainReceipt, NativeDrainError> {
    let validation = (|| {
        config.validate()?;
        if device.layer() != config.device.native.layer
            || link.binding != config.base_session_config()?
        {
            return Err(invalid("native drain device binding"));
        }
        Actor::new(&link, config)
    })();
    let mut actor = validation.map_err(|reason| NativeDrainError {
        reason,
        progress: DrainProgress::default(),
    })?;
    let proof = pump(&mut device, &mut link, config, &mut stop, &mut actor).await;
    let (local, peer, deadline) = proof.map_err(|reason| NativeDrainError {
        reason,
        progress: actor.snapshot(),
    })?;
    // Keep both original packet handles alive while the consuming control owner
    // joins its own tasks. In particular, dropping receiver would close handoffs.
    let DrainingLink {
        owner,
        sender,
        receiver,
        ..
    } = link;
    let result = timeout_at(deadline, owner.close()).await;
    let carrier = match result {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(reason)) => {
            return Err(NativeDrainError {
                reason,
                progress: actor.snapshot(),
            });
        }
        Err(_) => {
            return Err(NativeDrainError {
                reason: io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native carrier close exceeded original deadline",
                ),
                progress: actor.snapshot(),
            });
        }
    };
    drop((sender, receiver));
    if Instant::now() >= deadline {
        return Err(NativeDrainError {
            reason: io::Error::new(
                io::ErrorKind::TimedOut,
                "native close completed after deadline",
            ),
            progress: actor.snapshot(),
        });
    }
    Ok(NativeDrainReceipt {
        local,
        peer,
        deadline,
        carrier,
    })
}
async fn pump<D: PacketDevice<Error = io::Error>>(
    device: &mut D,
    link: &mut DrainingLink,
    config: DrainConfig,
    stop: &mut ShutdownSignal,
    a: &mut Actor,
) -> io::Result<(NativeFence, NativeFence, Instant)> {
    let codec = config.device.native.codec()?;
    let started = Instant::now();
    let mut local_requested = false;
    let mut timer = interval(config.device.native.poll_interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            request=&mut stop.0,if !local_requested => {
                let at=request.map_err(|_|io::Error::new(io::ErrorKind::Interrupted,"native shutdown producer canceled"))?;
                a.shorten(at.checked_add(config.drain_timeout).ok_or_else(||invalid("native request deadline overflow"))?);a.expired()?;
                link.owner.request()?;a.requested=true;local_requested=true;
            },
            _=async {match a.deadline {Some(deadline)=>tokio::time::sleep_until(deadline).await,None=>std::future::pending().await}}=> {return Err(io::Error::new(io::ErrorKind::TimedOut,"original native drain deadline expired"));},
            changed=link.owner.changed()=>{a.counts.control=Some(changed?);},
            result=async {match &mut a.admission {Some(f)=>f.await,None=>std::future::pending().await}}=> {
                let bytes=result.map_err(carrier_error)?;
                increment(&mut a.counts.accepted.sources)?;add(&mut a.counts.accepted.source_bytes,bytes)?;
                a.admission=None;a.admission_bytes=0;
            },
            received=link.receiver.receive(&mut a.source),if a.native.len()<config.device.native.queue_packets && a.counts.control.and_then(|s|s.peer).is_none_or(|p|a.counts.sources_received!=p.fence().sources) => {
                let length=received.map_err(carrier_error)?;increment(&mut a.counts.sources_received)?;add(&mut a.counts.source_bytes_received,length)?;
                if !a.reassembly.expire(ticks(started.elapsed())?).map_err(io::Error::other)?.is_empty() {return Err(io::Error::new(io::ErrorKind::TimedOut,"native reassembly expired"));}
                match a.reassembly.accept(&a.source[..length],ticks(started.elapsed())?,&mut a.record).map_err(io::Error::other)? {
                    ReassemblyStatus::Pending {message,..} if message.0==a.counts.native_completed=>{},
                    ReassemblyStatus::Duplicate {message} if message.0<=a.counts.native_completed=>{},
                    ReassemblyStatus::Complete {message,length} if message.0==a.counts.native_completed=>{
                        if config.device.native.compression==Compression::None && a.record.get(4)!=Some(&0) {return Err(invalid("native compression mismatch"));}
                        let packet=codec.decode_vec(&a.record[..length]).map_err(io::Error::other)?;
                        if !packet_valid(config.device.native.layer,&packet) {return Err(invalid("invalid decoded native original"));}
                        increment(&mut a.counts.native_completed)?;add(&mut a.counts.native_bytes_completed,packet.len())?;
                        a.native_bytes=a.native_bytes.checked_add(packet.len()).ok_or_else(||invalid("native queue bytes"))?;a.native.push_back(packet);
                    },
                    _=>return Err(invalid("native message sequence gap")),
                }
            },
            // A perpetually ready timer must not starve retained I/O work.
            _=timer.tick()=>{},
        }
        let state = link.owner.state()?;
        a.counts.control = Some(state);
        if let Some(deadline) = state.deadline {
            a.shorten(deadline);
            a.requested = true;
        }
        a.expired()?;
        if !a
            .reassembly
            .expire(ticks(started.elapsed())?)
            .map_err(io::Error::other)?
            .is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "native reassembly expired",
            ));
        }
        for _ in 0..config.device.work_limit {
            a.expired()?;
            let Some(packet) = a.native.front() else {
                break;
            };
            // Preflight counters before an irreversible native write.
            let count = a
                .counts
                .native_confirmed
                .checked_add(1)
                .ok_or_else(|| invalid("native confirmation count"))?;
            let bytes = a
                .counts
                .native_bytes_confirmed
                .checked_add(packet.len() as u64)
                .ok_or_else(|| invalid("native confirmation bytes"))?;
            match device.transmit(packet) {
                Ok(()) => {
                    a.native_bytes -= packet.len();
                    a.native.pop_front();
                    a.counts.native_confirmed = count;
                    a.counts.native_bytes_confirmed = bytes;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if !a.requested
            && a.fragments.is_empty()
            && a.admission.is_none()
            && let Some(length) = device.receive(&mut a.packet)?
        {
            if length > config.device.native.max_packet
                || length > a.packet.len()
                || !packet_valid(config.device.native.layer, &a.packet[..length])
            {
                return Err(invalid("invalid or oversized native ingress"));
            }
            let record = codec
                .encode_vec(&a.packet[..length])
                .map_err(io::Error::other)?;
            let batch = a.fragmenter.fragment(&record).map_err(io::Error::other)?;
            a.fragment_bytes = batch
                .fragments
                .iter()
                .try_fold(0usize, |sum, part| sum.checked_add(part.len()))
                .ok_or_else(|| invalid("native fragment bytes"))?;
            a.fragments = batch.fragments.into();
            increment(&mut a.counts.accepted.packets)?;
            add(&mut a.counts.accepted.native_bytes, length)?;
        }
        if a.admission.is_none()
            && let Some(bytes) = a.fragments.pop_front()
        {
            a.admission_bytes = bytes.len();
            a.fragment_bytes -= bytes.len();
            let sender = link.sender.clone();
            a.admission = Some(Box::pin(async move {
                sender.send(&bytes).await?;
                Ok(bytes.len())
            }));
        }
        if a.requested && a.fragments.is_empty() && a.admission.is_none() && state.local.is_none() {
            match link.owner.seal() {
                Ok(seal) => {
                    if (seal.sources(), seal.bytes())
                        != (a.counts.accepted.sources, a.counts.accepted.source_bytes)
                    {
                        return Err(invalid("native actor/carrier source prefix mismatch"));
                    }
                    link.owner.publish(a.counts.accepted, &seal)?;
                }
                Err(carrier::Error::Busy) => {}
                Err(error) => return Err(carrier_error(error)),
            }
        }
        if let Some(peer) = state.peer
            && !state.peer_acknowledged
            && a.compare_peer(peer.fence())?
        {
            link.owner.ack(&peer)?;
        }
        let state = link.owner.state()?;
        a.counts.control = Some(state);
        if state.ready() {
            let local = state
                .local
                .ok_or_else(|| invalid("native local fence absent"))?;
            let peer = state
                .peer
                .ok_or_else(|| invalid("native peer fence absent"))?
                .fence();
            if local != a.counts.accepted
                || !a.compare_peer(peer)?
                || !a.fragments.is_empty()
                || a.admission.is_some()
            {
                return Err(invalid("native close ownership proof mismatch"));
            }
            return Ok((
                local,
                peer,
                a.deadline
                    .ok_or_else(|| invalid("native deadline absent"))?,
            ));
        }
    }
}

#[cfg(test)]
mod tests;

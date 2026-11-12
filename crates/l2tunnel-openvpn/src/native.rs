//! Additive authenticated native-fence capability. Native confirmation remains the
//! responsibility of the adapter holding the actual device and accepted originals.
use crate::runtime::Shared;
use crate::{Carrier, CloseReceipt, Config, Control, Error, PacketReceiver, PacketSender};
use l2tunnel_auth::{SessionConfig, SessionInfo};
use l2tunnel_core::ConfigDigest;
use ring::digest;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{Instant, timeout_at},
};

pub(crate) const REQUEST: u8 = 6;
pub(crate) const FENCE: u8 = 7;
pub(crate) const NATIVE_ACK: u8 = 8;
pub(crate) const FRAME_BYTES: usize = 112;
pub(crate) const FRAME_SLOTS: usize = 8;

/// Separately negotiated native-drain policy; legacy factories keep OVC1 unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDrainConfig {
    carrier: Config,
    timeout: Duration,
}
impl NativeDrainConfig {
    /// Bind the existing complete policy and an integral-microsecond finite deadline.
    pub fn new(carrier: Config, timeout: Duration) -> Result<Self, Error> {
        carrier.validate()?;
        if !(Duration::from_millis(1)..=Duration::from_secs(120)).contains(&timeout)
            || !timeout.subsec_nanos().is_multiple_of(1000)
        {
            return Err(Error::Configuration("native drain duration"));
        }
        Ok(Self { carrier, timeout })
    }
    /// Original policy, before additive native-profile domain separation.
    pub const fn carrier(&self) -> Config {
        self.carrier
    }
    /// One original upper-layer drain allowance, including carrier shutdown.
    pub const fn drain_timeout(&self) -> Duration {
        self.timeout
    }
    /// Actual TLS/member configuration accepted by native-profile factories.
    pub fn session_config(&self) -> Result<SessionConfig, Error> {
        self.effective()?.session_config()
    }
    pub(crate) fn effective(&self) -> Result<Config, Error> {
        // The final Config digest includes every original carrier field. Only its
        // shared upper-layer base is separated here, preserving pair base equality.
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(b"l2tunnel/openvpn-native-control/v2\0");
        hash.update(&self.carrier.base.digest.0);
        for value in [
            FRAME_BYTES as u64,
            FRAME_SLOTS as u64,
            self.timeout.as_micros() as u64,
        ] {
            hash.update(&value.to_be_bytes());
        }
        let mut config = self.carrier;
        let mut bytes = [0; 32];
        bytes.copy_from_slice(hash.finish().as_ref());
        config.base.digest = ConfigDigest(bytes);
        config.validate()?;
        Ok(config)
    }
}
/// Exact cumulative native and carrier-source prefixes, never sampled queue lengths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeFence {
    /// Whole native originals accepted/confirmed.
    pub packets: u64,
    /// Sum of uncompressed native original lengths.
    pub native_bytes: u64,
    /// Complete recovery sources, exclusive from source zero.
    pub sources: u64,
    /// Sum of complete recovery source lengths.
    pub source_bytes: u64,
}
impl NativeFence {
    pub(crate) fn fields(self) -> [u64; 4] {
        [
            self.packets,
            self.native_bytes,
            self.sources,
            self.source_bytes,
        ]
    }
    pub(crate) fn from_fields(v: [u64; 4]) -> Self {
        Self {
            packets: v[0],
            native_bytes: v[1],
            sources: v[2],
            source_bytes: v[3],
        }
    }
    fn validate(self) -> Result<(), Error> {
        if (self.packets == 0) != (self.native_bytes == 0)
            || (self.sources == 0) != (self.source_bytes == 0)
            || self.packets > self.native_bytes
            || self.sources > self.source_bytes
            || self.packets > self.sources
        {
            return Err(Error::Configuration("native fence geometry"));
        }
        Ok(())
    }
}
/// A source seal minted only from this capability's authoritative send owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceFence {
    scope: [u8; 32],
    sources: u64,
    bytes: u64,
}
impl SourceFence {
    /// Unique sources actually admitted before the irreversible send seal.
    pub const fn sources(self) -> u64 {
        self.sources
    }
    /// Source bytes actually admitted before the irreversible send seal.
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}
/// A fence received through actual authenticated control on this logical capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerFence {
    scope: [u8; 32],
    fence: NativeFence,
}
impl PeerFence {
    /// Exact authenticated peer prefix to compare against actual native confirmation.
    pub const fn fence(self) -> NativeFence {
        self.fence
    }
}
/// Bounded authoritative control snapshot. Native counters are asserted by its adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeControlState {
    /// First local request or authenticated peer request, never refreshed.
    pub requested_at: Option<Instant>,
    /// Original request plus the negotiated allowance.
    pub deadline: Option<Instant>,
    /// Local immutable published fence.
    pub local: Option<NativeFence>,
    /// Actual peer fence, if received.
    pub peer: Option<PeerFence>,
    /// Peer acknowledged the exact local fence.
    pub local_acknowledged: bool,
    /// Local adapter confirmed and acknowledged the exact peer fence.
    pub peer_acknowledged: bool,
    /// Request, local fence and peer acknowledgment passed actual TLS flush.
    pub controls_flushed: bool,
    /// Secondary-lane Close is retained until the ordered management proof arrives.
    /// This is not acceptance of carrier close or proof of native confirmation.
    pub secondary_close_pending: bool,
}
impl NativeControlState {
    /// All native proofs and local typed-control flushes precede carrier close.
    pub const fn ready(self) -> bool {
        self.local.is_some()
            && self.peer.is_some()
            && self.local_acknowledged
            && self.peer_acknowledged
            && self.controls_flushed
    }
}
#[derive(Default)]
struct Phase {
    snapshot: NativeControlState,
    peer_requested: bool,
    flushed: u8,
}
pub(crate) struct Domain {
    pub scope: [u8; 32],
    send: Arc<Shared>,
    receive: Arc<Shared>,
    slots: usize,
    timeout: Duration,
    phase: Mutex<Phase>,
    changed: watch::Sender<u64>,
}
impl Domain {
    pub fn new(
        scope: [u8; 32],
        send: Arc<Shared>,
        receive: Arc<Shared>,
        slots: usize,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            scope,
            send,
            receive,
            slots,
            timeout,
            phase: Mutex::new(Phase::default()),
            changed: watch::channel(0).0,
        })
    }
    fn modify<T>(&self, f: impl FnOnce(&mut Phase) -> Result<T, Error>) -> Result<T, Error> {
        let mut phase = self.phase.lock().map_err(|_| Error::Closed)?;
        let result = f(&mut phase)?;
        self.changed
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        Ok(result)
    }
    pub fn state(&self) -> Result<NativeControlState, Error> {
        for shared in [&self.send, &self.receive] {
            if *shared.terminal.borrow() != Some(crate::Terminal::Clean) {
                shared.check()?;
            }
        }
        Ok(self.phase.lock().map_err(|_| Error::Closed)?.snapshot)
    }
    async fn wait_changed(
        &self,
        changes: &mut watch::Receiver<u64>,
    ) -> Result<NativeControlState, Error> {
        // Subscribe before checking: either the current terminal is observed here
        // or its later transition wakes the wait. Both physical bulk lanes count.
        let mut send = self.send.terminal.subscribe();
        let mut receive = self.receive.terminal.subscribe();
        let send_live = send.borrow().is_none();
        let receive_live = receive.borrow().is_none();
        // Classify terminal state after guards: a failure cannot become a disabled
        // watch source between a successful health check and guard capture.
        let state = self.state()?;
        if state.ready() && (!send_live || !receive_live) {
            return Ok(state);
        }
        // A clean lane is a completed watch source, not a perpetually ready
        // event while the other lane still owns a pending native ACK flush.
        tokio::select! { _=changes.changed()=>{}, _=send.changed(),if send_live=>{}, _=receive.changed(),if receive_live=>{} }
        self.state()
    }
    fn start(&self, phase: &mut Phase, now: Instant) -> Result<(), Error> {
        if phase.snapshot.requested_at.is_none() {
            phase.snapshot.deadline = Some(
                now.checked_add(self.timeout)
                    .ok_or(Error::Configuration("native deadline overflow"))?,
            );
            phase.snapshot.requested_at = Some(now);
        }
        Ok(())
    }
    pub fn request(&self) -> Result<(), Error> {
        self.send.check()?;
        self.receive.check()?;
        self.modify(|p| self.start(p, Instant::now()))
    }
    fn seal(&self) -> Result<SourceFence, Error> {
        self.state()?;
        if self.state()?.requested_at.is_none() {
            return Err(Error::Configuration("native request required"));
        }
        self.send.modify(|s| {
            if s.status.closing || s.status.terminal.is_some() {
                return Err(Error::Closed);
            }
            if self.send.send_slots.available_permits() != self.slots {
                return Err(Error::Busy);
            }
            s.sources.sealed = true;
            Ok(SourceFence {
                scope: self.scope,
                sources: s.status.admitted_packets,
                bytes: s.sources.admitted_bytes,
            })
        })
    }
    fn publish(&self, packets: u64, bytes: u64, seal: &SourceFence) -> Result<(), Error> {
        self.state()?;
        if seal.scope != self.scope {
            return Err(Error::Configuration("foreign source seal"));
        }
        self.send.modify(|s| {
            if !s.sources.sealed
                || seal.sources != s.status.admitted_packets
                || seal.bytes != s.sources.admitted_bytes
            {
                return Err(Error::Configuration("source seal mismatch"));
            }
            Ok(())
        })?;
        let fence = NativeFence {
            packets,
            native_bytes: bytes,
            sources: seal.sources,
            source_bytes: seal.bytes,
        };
        fence.validate()?;
        self.modify(|p| {
            if p.snapshot.requested_at.is_none() || p.snapshot.local.is_some_and(|old| old != fence)
            {
                return Err(Error::Configuration("local native fence state"));
            }
            p.snapshot.local = Some(fence);
            Ok(())
        })
    }
    fn ack(&self, peer: &PeerFence) -> Result<(), Error> {
        self.state()?;
        self.modify(|p| {
            if peer.scope != self.scope || p.snapshot.peer != Some(*peer) {
                return Err(Error::Configuration("foreign peer fence"));
            }
            self.receive.modify(|s| {
                if s.status.delivered_packets != peer.fence.sources
                    || s.sources.consumed_bytes != peer.fence.source_bytes
                {
                    return Err(Error::Busy);
                }
                Ok(())
            })?;
            p.snapshot.peer_acknowledged = true;
            Ok(())
        })
    }
    pub fn accept(&self, kind: u8, fence: NativeFence) -> Result<bool, Error> {
        self.modify(|p| match kind {
            REQUEST => {
                if fence != NativeFence::default() {
                    return Err(Error::Configuration("request fence fields"));
                }
                if p.peer_requested {
                    return Ok(false);
                }
                self.start(p, Instant::now())?;
                p.peer_requested = true;
                Ok(true)
            }
            FENCE => {
                fence.validate()?;
                if !p.peer_requested {
                    return Err(Error::Configuration("fence before request"));
                }
                let peer = PeerFence {
                    scope: self.scope,
                    fence,
                };
                if let Some(old) = p.snapshot.peer {
                    return if old == peer {
                        Ok(false)
                    } else {
                        Err(Error::Configuration("altered peer fence"))
                    };
                }
                self.receive.modify(|s| {
                    if s.sources.accepted_prefix > fence.sources
                        || s.status.delivered_packets > fence.sources
                        || s.sources.consumed_bytes > fence.source_bytes
                        || (s.status.delivered_packets == fence.sources
                            && s.sources.consumed_bytes != fence.source_bytes)
                    {
                        return Err(Error::Configuration("peer fence below accepted sources"));
                    }
                    s.sources.ceiling = Some((fence.sources, fence.source_bytes));
                    Ok(())
                })?;
                p.snapshot.peer = Some(peer);
                Ok(true)
            }
            NATIVE_ACK => {
                if p.snapshot.local != Some(fence) {
                    return Err(Error::Configuration("native acknowledgment mismatch"));
                }
                if p.snapshot.local_acknowledged {
                    return Ok(false);
                }
                p.snapshot.local_acknowledged = true;
                Ok(true)
            }
            _ => Err(Error::Configuration("native control kind")),
        })
    }
    pub fn secondary_close(&self, pending: bool) -> Result<(), Error> {
        self.modify(|p| {
            if p.snapshot.requested_at.is_none() {
                return Err(Error::Configuration(
                    "secondary Close before native request",
                ));
            }
            p.snapshot.secondary_close_pending = pending;
            Ok(())
        })
    }
    pub fn flushed(&self, kind: u8) -> Result<(), Error> {
        let bit = match kind {
            REQUEST => 1,
            FENCE => 2,
            NATIVE_ACK => 4,
            _ => return Ok(()),
        };
        self.modify(|p| {
            p.flushed |= bit;
            p.snapshot.controls_flushed = p.flushed == 7;
            Ok(())
        })
    }
    pub fn proof(&self) -> Result<bool, Error> {
        let s = self.state()?;
        Ok(s.local.is_some() && s.peer.is_some() && s.local_acknowledged && s.peer_acknowledged)
    }
    fn deadline(&self) -> Result<Instant, Error> {
        let s = self.state()?;
        if !s.ready() {
            return Err(Error::Busy);
        }
        let deadline = s
            .deadline
            .ok_or(Error::Configuration("native request missing"))?;
        if Instant::now() >= deadline {
            return Err(Error::IncompleteClose);
        }
        Ok(deadline)
    }
}
/// Native control attachment created privately after actual authentication/pair join.
#[derive(Clone)]
pub(crate) struct Attachment {
    pub domain: Arc<Domain>,
    pub management: bool,
}
/// Actual full-duplex native-drain capability; no conversion from legacy sessions.
pub struct NativeCarrier {
    pub(crate) carrier: Carrier,
    pub(crate) domain: Arc<Domain>,
}
impl NativeCarrier {
    /// Actual member-authenticated metadata with the native profile digest.
    pub fn info(&self) -> &SessionInfo {
        self.carrier.info()
    }
    /// Transfer original carrier owners and the logical native-fence controller.
    pub fn split(self) -> (NativeControl, PacketSender, PacketReceiver) {
        let (control, sender, receiver) = self.carrier.split();
        (
            NativeControl {
                changes: self.domain.changed.subscribe(),
                domain: self.domain,
                control,
            },
            sender,
            receiver,
        )
    }
}
/// Retained native/control owner. Dropping it cancels the original carrier tasks.
pub struct NativeControl {
    domain: Arc<Domain>,
    changes: watch::Receiver<u64>,
    control: Control,
}
impl NativeControl {
    /// Freeze intent; the adapter must stop native reads and drain accepted originals.
    pub fn request_stop(&self) -> Result<(), Error> {
        self.domain.request()
    }
    /// Read authoritative bounded control state.
    pub fn state(&self) -> Result<NativeControlState, Error> {
        self.domain.state()
    }
    /// Wait for a control change or original carrier termination.
    pub async fn changed(&mut self) -> Result<NativeControlState, Error> {
        self.domain.wait_changed(&mut self.changes).await
    }
    /// Irreversibly seal admission; Busy includes already reserved/in-flight sends.
    pub fn seal_send(&self) -> Result<SourceFence, Error> {
        self.domain.seal()
    }
    /// Publish the adapter's accepted native prefix and actual source seal.
    pub fn publish_fence(
        &self,
        packets: u64,
        bytes: u64,
        sources: &SourceFence,
    ) -> Result<(), Error> {
        self.domain.publish(packets, bytes, sources)
    }
    /// Assert actual native confirmation of this peer fence; source equality is checked.
    pub fn ack_peer_native(&self, peer: &PeerFence) -> Result<(), Error> {
        self.domain.ack(peer)
    }
    /// Close only after native proofs, within the original native deadline.
    pub async fn close(self) -> Result<CloseReceipt, Error> {
        let deadline = self.domain.deadline()?;
        let receipt = timeout_at(deadline, self.control.close())
            .await
            .map_err(|_| Error::IncompleteClose)??;
        if Instant::now() >= deadline {
            return Err(Error::IncompleteClose);
        }
        Ok(receipt)
    }
}

pub(crate) fn full_scope(info: SessionInfo) -> [u8; 32] {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"l2tunnel/openvpn-native-full/v2\0");
    hash.update(&info.session_id);
    hash.update(&info.config.digest.0);
    hash.update(&info.member.0);
    hash.update(&info.server.0);
    let mut bytes = [0; 32];
    bytes.copy_from_slice(hash.finish().as_ref());
    bytes
}

/// Authenticate the additive full-duplex native profile on this exact UDP socket.
pub async fn client_connect_native(
    socket: tokio::net::UdpSocket,
    config: NativeDrainConfig,
    credentials: crate::ClientCredentials<'_>,
) -> Result<NativeCarrier, Error> {
    let started = Instant::now();
    let effective = config.effective()?;
    if effective.profile.traffic != crate::Traffic::FullDuplex {
        return Err(Error::Configuration(
            "native full factory requires full lane",
        ));
    }
    let budget = crate::budget::Budget::new(effective.wire_budget, started);
    let prepared =
        crate::runtime::prepare_client(socket, effective, credentials, started, budget).await?;
    enable_full(prepared, config.timeout).await
}
/// Accept the genuine additive profile, retaining the same verified control stream.
pub async fn server_accept_native(
    socket: tokio::net::UdpSocket,
    config: NativeDrainConfig,
    credentials: crate::ServerCredentials<'_>,
) -> Result<NativeCarrier, Error> {
    let started = Instant::now();
    let effective = config.effective()?;
    if effective.profile.traffic != crate::Traffic::FullDuplex {
        return Err(Error::Configuration(
            "native full factory requires full lane",
        ));
    }
    let budget = crate::budget::Budget::new(effective.wire_budget, started);
    let prepared =
        crate::runtime::prepare_server(socket, effective, credentials, started, budget).await?;
    enable_full(prepared, config.timeout).await
}
async fn enable_full(
    prepared: crate::runtime::Prepared,
    timeout: Duration,
) -> Result<NativeCarrier, Error> {
    let shared = prepared.control.shared.clone();
    let domain = Domain::new(
        full_scope(*prepared.connection.info()),
        shared.clone(),
        shared,
        prepared.config.packet_slots,
        timeout,
    );
    let carrier = crate::runtime::enable_native(
        prepared,
        Some(Attachment {
            domain: domain.clone(),
            management: true,
        }),
    )
    .await?;
    Ok(NativeCarrier { carrier, domain })
}
/// Actual joined paired capability with one logical native control owner.
pub struct NativePairedCarrier {
    pub(crate) carrier: crate::PairedCarrier,
    pub(crate) domain: Arc<Domain>,
}
impl NativePairedCarrier {
    /// Actual two-lane join metadata, binding both session IDs and identities.
    pub fn info(&self) -> &crate::PairInfo {
        self.carrier.info()
    }
    /// Transfer both original carrier owners and the usable bulk handles.
    pub fn split(self) -> (NativePairControl, PacketSender, PacketReceiver) {
        let (control, sender, receiver) = self.carrier.split();
        (
            NativePairControl {
                changes: self.domain.changed.subscribe(),
                domain: self.domain,
                control,
            },
            sender,
            receiver,
        )
    }
}
/// Logical native control and both retained physical lane owners.
pub struct NativePairControl {
    domain: Arc<Domain>,
    changes: watch::Receiver<u64>,
    control: crate::PairControl,
}
impl NativePairControl {
    /// Request the one immutable native drain deadline across both lanes.
    pub fn request_stop(&self) -> Result<(), Error> {
        self.domain.request()
    }
    /// Read the logical native phases, independently of per-lane snapshots.
    pub fn state(&self) -> Result<NativeControlState, Error> {
        self.domain.state()
    }
    /// Wait for logical phase change or lane termination.
    pub async fn changed(&mut self) -> Result<NativeControlState, Error> {
        self.domain.wait_changed(&mut self.changes).await
    }
    /// Seal the actual local bulk sender, including all reserved capacity.
    pub fn seal_send(&self) -> Result<SourceFence, Error> {
        self.domain.seal()
    }
    /// Bind the local accepted native prefix to its actual bulk source seal.
    pub fn publish_fence(
        &self,
        packets: u64,
        bytes: u64,
        sources: &SourceFence,
    ) -> Result<(), Error> {
        self.domain.publish(packets, bytes, sources)
    }
    /// Assert native confirmation on the actual peer bulk receive lane.
    pub fn ack_peer_native(&self, peer: &PeerFence) -> Result<(), Error> {
        self.domain.ack(peer)
    }
    /// Require native proof then close both lanes within the original logical deadline.
    pub async fn close(self) -> Result<[CloseReceipt; 2], Error> {
        let deadline = self.domain.deadline()?;
        let receipt = timeout_at(deadline, self.control.close())
            .await
            .map_err(|_| Error::IncompleteClose)??;
        if Instant::now() >= deadline {
            return Err(Error::IncompleteClose);
        }
        Ok(receipt)
    }
}
/// Authenticate and join two complementary lanes before installing native control.
pub async fn client_pair_native(
    sockets: [tokio::net::UdpSocket; 2],
    configs: [NativeDrainConfig; 2],
    credentials: crate::ClientPairCredentials<'_>,
) -> Result<NativePairedCarrier, Error> {
    if configs[0].timeout != configs[1].timeout {
        return Err(Error::Configuration("native pair deadline mismatch"));
    }
    let (carrier, domain) = crate::pair::client_pair_profile(
        sockets,
        [configs[0].effective()?, configs[1].effective()?],
        credentials,
        Some(configs[0].timeout),
    )
    .await?;
    Ok(NativePairedCarrier {
        carrier,
        domain: domain.ok_or(Error::Configuration("native pair attachment missing"))?,
    })
}
/// Accept a genuine two-lane native profile, with first-lane control and shared budget.
pub async fn server_pair_native(
    sockets: [tokio::net::UdpSocket; 2],
    configs: [NativeDrainConfig; 2],
    credentials: crate::ServerPairCredentials<'_>,
) -> Result<NativePairedCarrier, Error> {
    if configs[0].timeout != configs[1].timeout {
        return Err(Error::Configuration("native pair deadline mismatch"));
    }
    let (carrier, domain) = crate::pair::server_pair_profile(
        sockets,
        [configs[0].effective()?, configs[1].effective()?],
        credentials,
        Some(configs[0].timeout),
    )
    .await?;
    Ok(NativePairedCarrier {
        carrier,
        domain: domain.ok_or(Error::Configuration("native pair attachment missing"))?,
    })
}

#[cfg(test)]
mod tests;

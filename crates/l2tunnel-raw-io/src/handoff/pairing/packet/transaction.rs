//! Exclusive transaction over actual original TLS and raw owners.
use super::super::super::{BridgeProof, SwitchExit, tls_owner::FrozenTls};
use super::*;
use gate::{Budget, Cell, Fence};
use l2tunnel_raw_tcp::{handoff::QuiescentTcp, packet};
use tokio::time::{sleep, sleep_until};
#[path = "compact_owner.rs"]
mod compact_owner;
#[path = "setup_diagnostics.rs"]
mod setup_diagnostics;
pub use setup_diagnostics::{
    SetupGateSnapshot, SetupLaneSnapshot, SetupOutcome, SetupPairStage, SetupSnapshot, SetupStage,
    SetupTransitionSnapshot,
};

// This fixed interval is already committed by PacketPolicy::digest.
const TRANSITION_RETRY_INTERVAL: Duration = Duration::from_millis(250);
const TRANSITION_MAX_COPIES: u16 = 32;
const TRANSITION_FINAL_RESERVE: u16 = 2;

struct Detached<I: PacketIo> {
    io: GateIo<I>,
    _tcp: QuiescentTcp,
    _frozen: FrozenTls,
    proof: wire::LaneProof,
    sealer: Option<PacketSealer>,
    final_prepared: Option<(compact::FinalMetadata, Option<compact::FinalControl>)>,
    pending: Option<Pending>,
    tracked: Option<RecordToken>,
    completed: Option<SentRecord>,
    prepare_observations: [PrepareSnapshot; 4],
    last_transition: Option<Instant>,
    last_transition_kind: Option<wire::Kind>,
    copies: u16,
    sent_hello: bool,
    sent_commit: bool,
    sent_ack: bool,
    hello: bool,
    hello_reply: bool,
    commit: bool,
    ack: bool,
    last_alive: Instant,
    last_ping: Instant,
    ping: Option<[u8; 8]>,
    pong: Option<[u8; 8]>,
    // Only genuine upper records require a report; Window never acknowledges itself.
    retirement_required: u64,
    retirement_reported: u64,
    early: Option<Cell>,
}
struct Pending {
    bootstrap: bool,
    bytes: Vec<u8>,
    end: u64,
    kind: wire::Kind,
    retired: u64,
}
impl<I: PacketIo> Detached<I> {
    fn buffer_snapshot(&self, now: Instant) -> Result<LaneBufferSnapshot, Error> {
        let state = lock(&self.io.state)?;
        let ([carrier_control, upper_control, bulk], selected_kind, selected_age_micros) =
            state.final_candidate_diagnostics(now);
        let fence = state.fence.as_ref();
        Ok(LaneBufferSnapshot {
            carrier_control,
            upper_control,
            bulk,
            candidate_capacity_packets: usize::from(state.policy.queue_packets) + 4,
            upper_bulk_shared_slot: state.policy.queue_packets == 1,
            bootstrap_records_outstanding: state.records_outstanding,
            bootstrap_control_queued: state
                .incoming
                .iter()
                .filter(|cell| cell.final_metadata.is_none() && cell.header.kind.control())
                .count(),
            total_gate_rejected_packets: state.rejected_packets,
            selected_kind,
            selected_age_micros,
            local_horizon_bytes: fence.map(|f| f.local_horizon),
            peer_horizon_bytes: fence.map(|f| f.peer_horizon),
            send_debt_bytes: fence.map(|f| f.allocated.saturating_sub(f.peer_retired)),
            retired_bytes: fence.map(|f| f.retired),
            prepared_payload_bytes: self
                .final_prepared
                .map_or(0, |(metadata, _)| metadata.payload_bytes()),
            pending_ip_bytes: self
                .pending
                .as_ref()
                .map_or(0, |pending| pending.bytes.len()),
            packet_io_pending: self.io.pending(),
            tracked: self.tracked.is_some(),
            completed: self.completed.is_some(),
            prepare: self.prepare_observations,
            send_io: self.io.send_observations,
            send_timing: self
                .io
                .send_timing
                .first()
                .map(|timing| timing.snapshot(now)),
            send_timing_capacity_bytes: self.io.send_timing.capacity()
                * std::mem::size_of::<super::send_timing::SendTiming>(),
        })
    }
    fn retirement_threshold(&self) -> Result<u64, Error> {
        let state = lock(&self.io.state)?;
        let maximum = u64::from(state.policy.mtu)
            .checked_sub(40)
            .ok_or(Error::Proof)?;
        let reserve = wire::Kind::Data
            .reserved_cells()
            .checked_mul(maximum)
            .ok_or(Error::Exhausted)?;
        let horizon = state.fence.as_ref().ok_or(Error::Proof)?.local_horizon;
        // Existing validation guarantees H >= 9M. With peer DATA credit
        // U = H - 8M, D < max(1, (U-M)/2) implies D+M <= U: another
        // maximum record fits before report eligibility. At H=9M every
        // genuine upper record reports. No timer or extra credit is created.
        horizon
            .checked_sub(reserve)
            .and_then(|usable| usable.checked_sub(maximum))
            .map(|margin| (margin / 2).max(1))
            .ok_or(Error::Proof)
    }
    fn stage(&mut self, kind: wire::Kind, body: &[u8], tx: [u8; 16]) -> Result<(), Error> {
        if self.pending.is_some() || self.io.pending() || self.final_prepared.is_some() {
            return Err(Error::Busy);
        }
        let mut state = lock(&self.io.state)?;
        let policy = state.policy;
        let config = state.config;
        if state.final_context.is_some()
            && (Instant::now() >= state.deadline
                || match kind {
                    wire::Kind::Data | wire::Kind::Feedback => {
                        state.bootstrap_filter.as_ref().is_none_or(|allow| {
                            !allow(super::compact::BootstrapDirection::Outgoing, body)
                        })
                    }
                    wire::Kind::Hello | wire::Kind::Commit | wire::Kind::CommitAck => false,
                    _ => true,
                })
        {
            return Err(Error::Proof);
        }
        if body.len() > policy.body_limit() {
            return Err(Error::Capacity);
        }
        let f = state.fence.as_mut().ok_or(Error::Proof)?;
        let payload_len = policy.overhead() - 40 + wire::HEADER + body.len();
        let end = f
            .allocated
            .checked_add(payload_len as u64)
            .ok_or(Error::Exhausted)?;
        let reserve = kind.reserved_cells() * (u64::from(policy.mtu) - 40);
        if end
            > f.peer_retired
                .checked_add(f.peer_horizon)
                .ok_or(Error::Exhausted)?
                .saturating_sub(reserve)
        {
            return Err(Error::Busy);
        }
        if !self.hello && end > u64::from(self.proof.peer_window) {
            return Err(Error::Exhausted);
        }
        let h = wire::Header {
            kind,
            transaction: tx,
            offset: f.allocated,
            retired: f.retired,
            right_edge: f
                .retired
                .checked_add(f.local_horizon)
                .ok_or(Error::Exhausted)?,
            body: u16::try_from(body.len()).map_err(|_| Error::Capacity)?,
        };
        let retired = h.retired;
        let plain = h.encode(body)?;
        let protected = self.sealer.as_mut().ok_or(Error::Proof)?.seal_vec(&plain)?;
        if protected.bytes.len() != payload_len {
            return Err(Error::Proof);
        }
        let sequence = crate::handoff::pairing::packet::sequence::wire(f.local, f.allocated);
        let ack = crate::handoff::pairing::packet::sequence::wire(f.peer, f.retired);
        let mut bytes = vec![0; payload_len + 40];
        packet::encode(
            config,
            sequence,
            ack,
            u16::try_from(f.local_horizon >> self.proof.scale).map_err(|_| Error::Proof)?,
            &protected.bytes,
            &mut bytes,
        )
        .map_err(|_| Error::Proof)?;
        state.fence.as_mut().ok_or(Error::Proof)?.allocated = end;
        self.pending = Some(Pending {
            bootstrap: true,
            bytes,
            end,
            kind,
            retired,
        });
        Ok(())
    }
    fn expire_controls(&mut self) -> Result<(), Error> {
        let retire_bootstrap = {
            let state = lock(&self.io.state)?;
            state.final_context.is_some() && Instant::now() >= state.deadline
        };
        if retire_bootstrap {
            self.sealer = None;
            if self
                .pending
                .as_ref()
                .is_some_and(|pending| pending.bootstrap)
            {
                if self.tracked.is_some() {
                    return Err(Error::Expired);
                }
                self.pending = None;
                self.io.cancel_pending();
            }
        }
        if Instant::now() >= lock(&self.io.state)?.deadline {
            if self.pending.as_ref().is_some_and(|p| {
                matches!(
                    p.kind,
                    wire::Kind::Hello | wire::Kind::Commit | wire::Kind::CommitAck
                )
            }) {
                self.pending = None;
                self.io.cancel_pending();
            }
            lock(&self.io.state)?.old_reply = None;
            if self.pending.is_none() {
                self.io.cancel_pending();
            }
        }
        Ok(())
    }
    fn progress(&mut self) -> Result<bool, Error> {
        self.expire_controls()?;
        self.io.drain_early()?;
        let mut progress = false;
        let mut input = [0; 65_536];
        self.io.receive(&mut input)?;
        self.expire_controls()?;
        if let Some(p) = self.pending.as_ref() {
            match self.io.send(&p.bytes) {
                Ok(()) => {
                    let p = self.pending.take().ok_or(Error::Proof)?;
                    // A staged header cannot grant physical report credit. Retain
                    // the exact snapshot until this same packet is accepted.
                    self.retirement_reported = self.retirement_reported.max(p.retired);
                    if !p.bootstrap && p.kind == wire::Kind::Ping {
                        // Retry spacing starts at actual acceptance, while the
                        // independent last_alive deadline remains unchanged.
                        self.last_ping = self.io.last_send_at.ok_or(Error::Proof)?;
                    }
                    if let Some(token) = self.tracked.take() {
                        if self.completed.is_some() {
                            return Err(Error::Proof);
                        }
                        self.completed = Some(SentRecord {
                            lane: if self.proof.lane == 0 {
                                PairLane::First
                            } else {
                                PairLane::Second
                            },
                            token,
                            sent_at: self.io.last_send_at.take().ok_or(Error::Proof)?,
                        });
                    }
                    lock(&self.io.state)?
                        .fence
                        .as_mut()
                        .ok_or(Error::Proof)?
                        .sent = p.end;
                    match p.kind {
                        wire::Kind::Hello => self.sent_hello = true,
                        wire::Kind::Commit => self.sent_commit = true,
                        wire::Kind::CommitAck => self.sent_ack = true,
                        _ => {}
                    }
                    if matches!(
                        p.kind,
                        wire::Kind::Hello | wire::Kind::Commit | wire::Kind::CommitAck
                    ) {
                        self.copies = self.copies.checked_add(1).ok_or(Error::Exhausted)?;
                        self.last_transition = Some(Instant::now());
                        self.last_transition_kind = Some(p.kind);
                    }
                    progress = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.expire_controls()?;
        // An exact retained old-ACK send shares the same one pending I/O token.
        // Never send it while a protected output is blocked.
        if self.pending.is_none() {
            let old = lock(&self.io.state)?.old_reply.take();
            if let Some(old) = old {
                match self.io.send(&old) {
                    Ok(()) => {
                        lock(&self.io.state)?.last_old = Some(Instant::now());
                        progress = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        lock(&self.io.state)?.old_reply = Some(old);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(progress)
    }
    // Hello cannot consume the last two existing attempts: each local role
    // still needs its Commit or CommitAck, including one possible lost copy.
    // Duplicate-triggered Hello replies use this same total per-lane budget.
    fn transition_kind(
        &self,
        client: bool,
        ready: bool,
        all_hello: bool,
        all_commit: bool,
    ) -> Option<wire::Kind> {
        if self.copies >= TRANSITION_MAX_COPIES {
            return None;
        }
        let hello = !all_hello
            || (self.hello_reply
                && (!client || self.last_transition_kind != Some(wire::Kind::Hello)));
        if hello && self.copies < TRANSITION_MAX_COPIES - TRANSITION_FINAL_RESERVE {
            Some(wire::Kind::Hello)
        } else if !all_hello {
            None
        } else if client && !ready {
            Some(wire::Kind::Commit)
        } else if !client && all_commit {
            Some(wire::Kind::CommitAck)
        } else {
            None
        }
    }
    fn retry_due(&self, now: Instant) -> bool {
        self.pending.is_none()
            && self.copies < TRANSITION_MAX_COPIES
            && self
                .last_transition
                .is_none_or(|t| now.saturating_duration_since(t) >= TRANSITION_RETRY_INTERVAL)
    }
}

/// From-birth setup future. Dropping it synchronously drops every original owner.
/// Borrowed polling cancellation retains all partial TLS and packet output.
pub struct PacketSetup<'a, I: PacketIo + Send + 'static> {
    setup: Option<PairSetup<'a, GateIo<I>>>,
    paired: Option<PairedRaw<GateIo<I>>>,
    states: [Option<Arc<Mutex<GateState>>>; 2],
    budget: SharedBudget,
    policy: PacketPolicy,
    policy_digest: [u8; 32],
    deadline: Instant,
    timer: Pin<Box<Sleep>>,
    tick: Pin<Box<Sleep>>,
    count: usize,
    client: bool,
    transaction: [u8; 16],
    stage: u8,
    staged: [bool; 2],
    received: [bool; 2],
    preparation: [u8; 32],
    armed: [u8; 32],
    frozen: [Option<FrozenTls>; 2],
    detached: [Option<Detached<I>>; 2],
    terminal_buffers: Vec<BufferSnapshot>,
    terminal_setup: Vec<SetupSnapshot>,
    carrier: Option<PacketCarrier<I>>,
    done: bool,
}
// No field is structurally pinned: every polled backend future/timer is in its
// own pinned allocation, and PacketIo is only called through ordinary &mut.
impl<I: PacketIo + Send + 'static> Unpin for PacketSetup<'_, I> {}
/// Live experimental protected carrier; no native credit or clean-close authority.
/// The caller must continue polling it while another peer is still setting up.
pub struct PacketCarrier<I: PacketIo + Send + 'static> {
    lanes: [Option<Detached<I>>; 2],
    terminal_sent: [Option<SentRecord>; 2],
    // One slot reserved before attachment, populated once before owner release.
    terminal_buffers: Vec<BufferSnapshot>,
    info: PairInfo,
    policy: PacketPolicy,
    policy_digest: [u8; 32],
    transaction: [u8; 16],
    armed: [u8; 32],
    local_hello: [u8; wire::HELLO],
    peer_hello: Option<[u8; wire::HELLO]>,
    commit_proof: Option<[u8; 32]>,
    deadline: Instant,
    timer: Pin<Box<Sleep>>,
    tick: Pin<Box<Sleep>>,
    budget: SharedBudget,
    records: VecDeque<ReceivedRecord>,
    ready: bool,
    fault: Option<Error>,
    cursor: usize,
    final_context: Option<[u8; 32]>,
}
fn recover<I: PacketIo>(inputs: RawInputs<GateIo<I>>) -> RawInputs<I> {
    let raw = |input: RawInput<GateIo<I>>| RawInput {
        config: input.config,
        io: input.io.original(),
    };
    match inputs {
        RawInputs::Full(a) => RawInputs::Full(raw(a)),
        RawInputs::Half { forward, reverse } => RawInputs::Half {
            forward: raw(forward),
            reverse: raw(reverse),
        },
    }
}
fn configuration<I: PacketIo + Send + 'static>(
    config: PacketPhaseConfig,
    a: Config,
    b: Option<Config>,
) -> Result<(PairConfig, [u8; 32], usize), Error> {
    config.packet.validate()?;
    if config.pair.messages.max_payload < 244
        || config.pair.messages.messages_per_direction < 5
        || config.pair.messages.bytes_per_direction < 912
    {
        return Err(Error::Configuration);
    }
    if a.mtu != usize::from(config.packet.mtu) || b.is_some_and(|b| b.mtu != a.mtu) {
        return Err(Error::Configuration);
    }
    let policy = config.packet.digest(config.pair.session.digest)?;
    let mut pair = config.pair;
    pair.session.digest = ConfigDigest(hash_parts(b"l2tunnel/raw-packet-pair/v1\0", &[&policy]));
    let profile = profile::validate_configs(a, b, pair)?;
    let retained = (profile.count as u64)
        .checked_mul(
            (u64::from(config.packet.queue_packets) + 11) * u64::from(config.packet.mtu)
                + 65_536
                + 2 * 128
                + 104,
        )
        .and_then(|n| n.checked_add(2 * 280 + 2 * 104))
        .ok_or(Error::Capacity)?;
    let peak = retained
        .checked_add(profile.count as u64 * (2 * u64::from(config.packet.mtu) + 64) + 512)
        .ok_or(Error::Capacity)?;
    if retained > 1_048_576 || peak > 2_097_152 {
        return Err(Error::Capacity);
    }
    profile
        .resources
        .retained_payload
        .checked_add(retained)
        .ok_or(Error::Capacity)?;
    profile
        .resources
        .peak_payload
        .checked_add(peak)
        .ok_or(Error::Capacity)?;
    // Concrete owner/future/crypto descriptor charges, before attachment.
    let range_capacity = GateState::planned_range_capacity_bytes(config.packet)?;
    let metadata = std::mem::size_of::<PacketSetup<'static, I>>()
        + std::mem::size_of::<PacketCarrier<I>>()
        + std::mem::size_of::<BufferSnapshot>()
        + std::mem::size_of::<SetupSnapshot>()
        + profile.count
            * (std::mem::size_of::<GateIo<I>>()
                + std::mem::size_of::<GateState>()
                + range_capacity
                + std::mem::size_of::<PacketOpener>()
                + std::mem::size_of::<PacketSealer>()
                + std::mem::size_of::<Detached<I>>()
                + 2 * std::mem::size_of::<Sleep>()
                + (usize::from(config.packet.queue_packets) + 16) * std::mem::size_of::<Cell>());
    if metadata > 1_048_576 {
        return Err(Error::Capacity);
    }
    // Packet setup passes GateIo<I> into the unchanged inner pair factory.
    // Check that exact concrete future/owner bound before either is created.
    super::super::metadata::<GateIo<I>>(profile.count, a)?;
    Ok((pair, policy, profile.count))
}

impl PacketPhaseConfig {
    /// Check the exact raw lane configuration and bounded packet/pair storage
    /// before opening either PacketIo owner. The type parameter must match the
    /// actual original I/O type because its retained metadata is charged.
    ///
    /// This performs no I/O, clock access, randomness, timer construction or
    /// owner creation and does not require a Tokio runtime. Canonical policy
    /// hashing uses bounded temporary storage. Success grants no setup authority;
    /// the actual factory repeats these checks and validates credentials/time.
    pub fn preflight<I: PacketIo + Send + 'static>(
        self,
        first: Config,
        second: Option<Config>,
    ) -> Result<(), Error> {
        configuration::<I>(self, first, second).map(|_| ())
    }
}

fn begin<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    credentials: Credentials<'a>,
    config: PacketPhaseConfig,
) -> Result<PacketSetup<'a, I>, PacketStartFailure<I>> {
    let start = Instant::now();
    let prepared = (|| {
        let (first, second) = inputs.configs();
        let (pair, policy, count) = configuration::<I>(config, first, second)?;
        let deadline = start.checked_add(pair.timeout).ok_or(Error::Expired)?;
        // Allocate every receive bitmap before consuming either original I/O
        // owner, so allocation refusal returns the unchanged inputs to the caller.
        let first_state = GateState::new(first, config.packet, deadline)?;
        let second_state = second
            .map(|value| GateState::new(value, config.packet, deadline))
            .transpose()?;
        // Terminal failure must retain scalar evidence without allocating or
        // keeping a large snapshot inline through every setup owner move.
        let mut terminal_buffers = Vec::new();
        terminal_buffers
            .try_reserve_exact(1)
            .map_err(|_| Error::Capacity)?;
        if terminal_buffers.capacity() != 1 {
            return Err(Error::Capacity);
        }
        let mut terminal_setup = Vec::new();
        terminal_setup
            .try_reserve_exact(1)
            .map_err(|_| Error::Capacity)?;
        if terminal_setup.capacity() != 1 {
            return Err(Error::Capacity);
        }
        Ok((
            pair,
            policy,
            deadline,
            count,
            first_state,
            second_state,
            terminal_buffers,
            terminal_setup,
        ))
    })();
    let (
        pair,
        policy_digest,
        deadline,
        count,
        first_state,
        second_state,
        terminal_buffers,
        terminal_setup,
    ) = match prepared {
        Ok(p) => p,
        Err(error) => {
            return Err(PacketStartFailure {
                inputs: Box::new(inputs),
                error,
            });
        }
    };
    let budget = Arc::new(Mutex::new(Budget::new(config.packet, start)));
    let mut states = [None, None];
    let client = matches!(credentials, Credentials::Client(..));
    let mut wrap = |input: RawInput<I>, state: GateState, index: usize| {
        let io = GateIo::new(input.io, state, budget.clone());
        if let Ok(mut state) = io.state.lock() {
            state.half = count == 2;
            state.lane = index;
            state.client = client;
        }
        states[index] = Some(io.state.clone());
        RawInput {
            config: input.config,
            io,
        }
    };
    let wrapped = match (inputs, second_state) {
        (RawInputs::Full(a), None) => RawInputs::Full(wrap(a, first_state, 0)),
        (RawInputs::Half { forward, reverse }, Some(second_state)) => RawInputs::Half {
            forward: wrap(forward, first_state, 0),
            reverse: wrap(reverse, second_state, 1),
        },
        (inputs, _) => {
            return Err(PacketStartFailure {
                inputs: Box::new(inputs),
                error: Error::Configuration,
            });
        }
    };
    let setup = match build_at(wrapped, credentials, pair, start) {
        Ok(setup) => setup,
        Err(f) => {
            return Err(PacketStartFailure {
                inputs: Box::new(recover(*f.inputs)),
                error: Error::Pair(f.error),
            });
        }
    };
    Ok(PacketSetup {
        setup: Some(setup),
        paired: None,
        states,
        budget,
        policy: config.packet,
        policy_digest,
        deadline,
        timer: Box::pin(sleep_until(deadline)),
        tick: Box::pin(sleep(Duration::from_millis(1))),
        count,
        client,
        transaction: [0; 16],
        stage: 0,
        staged: [false; 2],
        received: [false; 2],
        preparation: [0; 32],
        armed: [0; 32],
        frozen: [None, None],
        detached: [None, None],
        terminal_buffers,
        terminal_setup,
        carrier: None,
        done: false,
    })
}
/// Construct all original client owners with a single absolute transition deadline.
///
/// # Panics
/// The current Tokio runtime must have its time driver enabled.
pub fn begin_packet_client<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    tls: &'a ClientTls,
    name: &'a str,
    member: &'a MemberKey,
    config: PacketPhaseConfig,
) -> Result<PacketSetup<'a, I>, PacketStartFailure<I>> {
    begin(inputs, Credentials::Client(tls, name, member), config)
}
/// Construct all original server owners and finite protected packet policy.
///
/// # Panics
/// The current Tokio runtime must have its time driver enabled.
pub fn begin_packet_server<'a, I: PacketIo + Send + 'static>(
    inputs: RawInputs<I>,
    tls: &'a ServerTls,
    members: &'a MemberAllowlist,
    config: PacketPhaseConfig,
) -> Result<PacketSetup<'a, I>, PacketStartFailure<I>> {
    begin(inputs, Credentials::Server(tls, members), config)
}

impl<I: PacketIo + Send + 'static> PacketSetup<'_, I> {
    fn check(&self) -> Result<(), Error> {
        if Instant::now() >= self.deadline {
            Err(Error::Expired)
        } else {
            Ok(())
        }
    }
    fn install(&mut self) -> Result<(), Error> {
        let paired = self.paired.as_ref().ok_or(Error::Proof)?;
        self.transaction = wire::array(
            &hash_parts(
                b"l2tunnel/raw-packet-transaction/v1\0",
                &[&paired.info.transcript_digest, &self.policy_digest],
            )[..16],
        )?;
        let keys = &paired.group.keys.as_ref().ok_or(Error::Proof)?._values;
        for i in 0..self.count {
            let info = paired.info.lanes[i].ok_or(Error::Proof)?;
            let direction = if self.client {
                Direction::ServerToClient
            } else {
                Direction::ClientToServer
            };
            let index = i * 6 + if self.client { 5 } else { 4 };
            let mut state = lock(self.states[i].as_ref().ok_or(Error::Proof)?)?;
            state.transaction = self.transaction;
            state.expected_pair = paired.info.transcript_digest;
            state.session = info.session_id;
            state.opener = Some(PacketOpener::new(
                self.policy.datagram(info.session_id, i, direction),
                &keys[index],
            )?);
        }
        Ok(())
    }
    fn controls(&self, kind: u8, stage: [u8; 32]) -> Result<[[u8; wire::CONTROL]; 2], Error> {
        let pair = self
            .paired
            .as_ref()
            .ok_or(Error::Proof)?
            .info
            .transcript_digest;
        Ok(std::array::from_fn(|i| {
            if i < self.count {
                wire::control(kind, i, self.transaction, pair, self.policy_digest, stage)
            } else {
                [0; wire::CONTROL]
            }
        }))
    }
    fn control_turn(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let kind = match self.stage {
            1 => {
                if self.client {
                    1
                } else {
                    2
                }
            }
            2 => 3,
            3 => 4,
            _ => return Err(Error::Proof),
        };
        let peer_kind = if self.stage == 1 {
            if self.client { 2 } else { 1 }
        } else {
            kind
        };
        let digest = match self.stage {
            1 => [0; 32],
            2 => self.preparation,
            3 => self.armed,
            _ => return Err(Error::Proof),
        };
        let own = self.controls(kind, digest)?;
        let peer = self.controls(peer_kind, digest)?;
        let allow_send =
            self.stage != 1 || self.client || self.received[..self.count].iter().all(|b| *b);
        let paired = self.paired.as_mut().ok_or(Error::Proof)?;
        if allow_send {
            for (i, bytes) in own.iter().enumerate().take(self.count) {
                if !self.staged[i] {
                    paired.group.owners[i]
                        .as_mut()
                        .ok_or(Error::Proof)?
                        .stage_message(bytes)
                        .map_err(PairError::Message)?;
                    self.staged[i] = true;
                }
            }
        }
        paired.group.drive(cx)?;
        for (i, expected) in peer.iter().enumerate().take(self.count) {
            self.check()?;
            let paired = self.paired.as_mut().ok_or(Error::Proof)?;
            let owner = paired.group.owners[i].as_mut().ok_or(Error::Proof)?;
            if owner.status().send_pending
                && let Poll::Ready(r) = owner.poll_send(cx)
            {
                r.map_err(PairError::Message)?;
            }
            if !self.received[i] {
                if owner.message().is_none()
                    && let Poll::Ready(r) = owner.poll_receive(cx)
                {
                    r.map_err(PairError::Message)?;
                }
                if let Some(message) = owner.message() {
                    if message != expected {
                        return Err(Error::Proof);
                    }
                    self.received[i] = true;
                    if self.stage != 3 {
                        owner.consume_message().map_err(PairError::Message)?;
                    }
                }
            }
            self.check()?;
        }
        let paired = self.paired.as_ref().ok_or(Error::Proof)?;
        Ok(self.received[..self.count].iter().all(|b| *b)
            && self.staged[..self.count].iter().all(|b| *b)
            && paired.group.owners[..self.count]
                .iter()
                .all(|o| o.as_ref().is_some_and(|o| !o.status().send_pending)))
    }
    fn freeze(&mut self) -> Result<(), Error> {
        let seals = self.controls(4, self.armed)?;
        for (i, seal) in seals.into_iter().enumerate().take(self.count) {
            let paired = self.paired.as_mut().ok_or(Error::Proof)?;
            let shared = paired.group.observers[i]
                .as_ref()
                .ok_or(Error::Proof)?
                .clone();
            let owner = paired.group.owners[i].take().ok_or(Error::Proof)?;
            self.frozen[i] = Some(owner.freeze_terminal(ArmedLane { shared, seal })?);
            self.check()?;
        }
        for lane in self.frozen.iter_mut().flatten() {
            lane.request()?;
        }
        self.check()
    }
    fn collect(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        for i in 0..self.count {
            self.check()?;
            if self.detached[i].is_some() {
                self.detached[i].as_mut().ok_or(Error::Proof)?.progress()?;
                continue;
            }
            let paired = self.paired.as_mut().ok_or(Error::Proof)?;
            let result = paired.group.drivers[i]
                .as_mut()
                .ok_or(Error::Proof)?
                .as_mut()
                .poll(cx);
            self.check()?;
            if let Poll::Ready(result) = result {
                let parts = match result? {
                    SwitchExit::Handoff(p) => p,
                    SwitchExit::Clean(_) => return Err(Error::Proof),
                };
                self.paired.as_mut().ok_or(Error::Proof)?.group.drivers[i] = None;
                let frozen = self.frozen[i].take().ok_or(Error::Proof)?;
                let detached = self.detach(i, parts, frozen)?;
                self.detached[i] = Some(detached);
            }
            self.check()?;
        }
        Ok(self.detached[..self.count].iter().all(Option::is_some))
    }
    fn detach(
        &self,
        i: usize,
        parts: super::super::super::HandoffParts<GateIo<I>>,
        frozen: FrozenTls,
    ) -> Result<Detached<I>, Error> {
        let (io, tcp, bridge) = parts.into_parts();
        if !Arc::ptr_eq(&io.state, self.states[i].as_ref().ok_or(Error::Proof)?) {
            return Err(Error::Proof);
        }
        let snapshot = *tcp.snapshot();
        let t = snapshot.tcp;
        let messages = frozen.status();
        let records = messages.records;
        let written = records.outgoing.wire_bytes;
        let read = records.incoming.wire_bytes;
        if written == 0
            || read == 0
            || written >= 1 << 31
            || read >= 1 << 31
            || bridge.endpoint().written != written
            || bridge.endpoint().read != read
            || snapshot.progress.send_admitted != written
            || snapshot.progress.receive_consumed != read
            || t.timestamps_enabled
        {
            return Err(Error::Proof);
        }
        let local = t.send_next.0 as u32;
        let peer = t.receive_next.0 as u32;
        let (wire_next, wire_ack, wire_window) = lock(&io.state)?.last_wire.ok_or(Error::Proof)?;
        if wire_next != local || wire_ack != peer {
            return Err(Error::Proof);
        }
        let horizon = horizon(self.policy, wire_window, t.local_window_shift)?;
        let peer_scale = t.peer_window_shift.unwrap_or(0);
        let peer_horizon = horizon_bytes(self.policy, t.peer_window_bytes as u64, peer_scale)?;
        let pair = self.paired.as_ref().ok_or(Error::Proof)?;
        let actual = pair.info.lanes[i].ok_or(Error::Proof)?;
        let proof = wire::LaneProof {
            lane: i as u8,
            bulk: if self.count == 1 { 0 } else { i as u8 + 1 },
            role: if self.client { 1 } else { 2 },
            options: u8::from(t.peer_sack_permitted),
            session: actual.session_id,
            written,
            read,
            una: t.send_unacknowledged.0 as u32,
            next: local,
            receive: peer,
            ack: t.last_ack_sent.0 as u32,
            window: wire_window,
            scale: t.local_window_shift,
            peer_scale: t.peer_window_shift.unwrap_or(255),
            peer_window: u32::try_from(t.peer_window_bytes).map_err(|_| Error::Proof)?,
            mss: u16::try_from(t.peer_mss).map_err(|_| Error::Proof)?,
            available: u32::MAX - local,
            counters: counter_digest(messages, bridge),
        };
        wire::LaneProof::parse(&proof.encode())?;
        lock(&io.state)?.local_proof = Some(proof);
        let hello_payload = self.policy.overhead() - 40 + wire::HEADER + wire::HELLO;
        if hello_payload > t.peer_mss || hello_payload > t.peer_window_bytes {
            return Err(Error::Exhausted);
        }
        lock(&io.state)?.fence = Some(Fence {
            local,
            peer,
            receive_prefix: read,
            local_horizon: horizon,
            peer_horizon,
            peer_scale,
            window: wire_window,
            sent: 0,
            allocated: 0,
            retired: 0,
            peer_retired: 0,
        });
        let direction = if self.client {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let key_index = i * 6 + if self.client { 4 } else { 5 };
        let sealer = PacketSealer::new(
            self.policy.datagram(actual.session_id, i, direction),
            &pair.group.keys.as_ref().ok_or(Error::Proof)?._values[key_index],
        )?;
        Ok(Detached {
            io,
            _tcp: tcp,
            _frozen: frozen,
            proof,
            sealer: Some(sealer),
            final_prepared: None,
            pending: None,
            tracked: None,
            completed: None,
            prepare_observations: [PrepareSnapshot::default(); 4],
            last_transition: None,
            last_transition_kind: None,
            copies: 0,
            sent_hello: false,
            sent_commit: false,
            sent_ack: false,
            hello: false,
            hello_reply: false,
            commit: false,
            ack: false,
            last_alive: Instant::now(),
            last_ping: Instant::now(),
            ping: None,
            pong: None,
            retirement_required: 0,
            retirement_reported: 0,
            early: None,
        })
    }
    fn make_carrier(&mut self) -> Result<(), Error> {
        let info = self.paired.as_ref().ok_or(Error::Proof)?.info.clone();
        let hello = wire::Hello {
            count: self.count,
            pair: info.transcript_digest,
            armed: self.armed,
            lanes: std::array::from_fn(|i| self.detached[i].as_ref().map(|d| d.proof)),
        }
        .encode()?;
        self.carrier = Some(PacketCarrier {
            lanes: std::mem::take(&mut self.detached),
            terminal_sent: [None, None],
            terminal_buffers: std::mem::take(&mut self.terminal_buffers),
            info,
            policy: self.policy,
            policy_digest: self.policy_digest,
            transaction: self.transaction,
            armed: self.armed,
            local_hello: hello,
            peer_hello: None,
            commit_proof: None,
            deadline: self.deadline,
            timer: Box::pin(sleep_until(self.deadline)),
            tick: Box::pin(sleep(Duration::from_millis(1))),
            budget: self.budget.clone(),
            records: VecDeque::with_capacity(self.count * usize::from(self.policy.queue_packets)),
            ready: false,
            fault: None,
            cursor: 0,
            final_context: None,
        });
        self.paired = None;
        Ok(())
    }
    fn turn(&mut self, cx: &mut Context<'_>) -> Result<Option<PacketCarrier<I>>, Error> {
        self.check()?;
        lock(&self.budget)?.quota = 32;
        if self.stage == 0 {
            let setup = self.setup.as_mut().ok_or(Error::Proof)?;
            if let Poll::Ready(result) = Pin::new(setup).poll(cx) {
                self.paired = Some(result?);
                self.setup = None;
                self.install()?;
                self.stage = 1;
                cx.waker().wake_by_ref();
            }
        } else if self.stage <= 3 {
            if self.stage == 2
                && !self
                    .states
                    .iter()
                    .flatten()
                    .all(|s| lock(s).is_ok_and(|s| s.installed))
            {
                self.paired.as_mut().ok_or(Error::Proof)?.group.drive(cx)?;
            } else if self.control_turn(cx)? {
                match self.stage {
                    1 => {
                        let a = self.controls(1, [0; 32])?;
                        let b = self.controls(2, [0; 32])?;
                        self.preparation = wire::set_hash(
                            b"l2tunnel/raw-packet-prepared-set/v1\0",
                            &[a[0], a[1], b[0], b[1]],
                        );
                    }
                    2 => {
                        let a = self.controls(3, self.preparation)?;
                        self.armed = wire::set_hash(
                            b"l2tunnel/raw-packet-armed-set/v1\0",
                            &[a[0], a[1], a[0], a[1]],
                        );
                        for state in self.states.iter().flatten() {
                            let mut state = lock(state)?;
                            state.hello_allowed = true;
                            state.expected_armed = self.armed;
                        }
                    }
                    3 => self.freeze()?,
                    _ => return Err(Error::Proof),
                }
                self.stage += 1;
                self.staged = [false; 2];
                self.received = [false; 2];
                cx.waker().wake_by_ref();
            }
        } else if self.stage == 4 {
            if self.collect(cx)? {
                self.make_carrier()?;
                self.stage = 5;
                cx.waker().wake_by_ref();
            }
        } else {
            let carrier = self.carrier.as_mut().ok_or(Error::Proof)?;
            carrier.turn(cx)?;
            if carrier.ready {
                self.check()?;
                self.retain_setup_snapshot(SetupOutcome::Ready);
                return Ok(self.carrier.take());
            }
        }
        self.check()?;
        Ok(None)
    }
}
impl<I: PacketIo + Send + 'static> Future for PacketSetup<'_, I> {
    type Output = Result<PacketCarrier<I>, Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(Err(Error::Proof));
        }
        match this.turn(cx) {
            Ok(Some(carrier)) => {
                this.done = true;
                Poll::Ready(Ok(carrier))
            }
            Ok(None) => {
                if this.timer.as_mut().poll(cx).is_ready() {
                    this.retain_setup_snapshot(SetupOutcome::Failed);
                    this.done = true;
                    this.setup = None;
                    this.paired = None;
                    this.frozen = [None, None];
                    this.detached = [None, None];
                    this.carrier = None;
                    return Poll::Ready(Err(Error::Expired));
                }
                if this.tick.as_mut().poll(cx).is_ready() {
                    this.tick
                        .as_mut()
                        .reset(Instant::now() + Duration::from_millis(1));
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(e) => {
                this.retain_setup_snapshot(SetupOutcome::Failed);
                this.done = true;
                this.setup = None;
                this.paired = None;
                this.frozen = [None, None];
                this.detached = [None, None];
                this.carrier = None;
                Poll::Ready(Err(e))
            }
        }
    }
}
pub(super) fn horizon(policy: PacketPolicy, window: u16, shift: u8) -> Result<u64, Error> {
    horizon_bytes(policy, u64::from(window) << shift, shift)
}
fn horizon_bytes(policy: PacketPolicy, bytes: u64, shift: u8) -> Result<u64, Error> {
    if shift > 14 {
        return Err(Error::Proof);
    }
    let h = (u64::from(policy.horizon_bytes).min(bytes) >> shift) << shift;
    if h < 9 * (u64::from(policy.mtu) - 40) || h >> shift > u64::from(u16::MAX) {
        return Err(Error::Exhausted);
    }
    Ok(h)
}
fn counter_digest(m: MessageStatus, b: BridgeProof) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(400);
    for p in [m.records.incoming, m.records.outgoing] {
        for n in [
            p.wire_bytes,
            p.started_records,
            p.completed_records,
            u64::from(p.header_bytes),
            u64::from(p.body_remaining),
        ] {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
    }
    for p in [m.incoming, m.outgoing] {
        for n in [
            p.reserved_bytes,
            p.reserved_messages,
            p.plaintext_bytes,
            p.started_messages,
            p.completed_messages,
        ] {
            bytes.extend_from_slice(&n.to_be_bytes());
        }
    }
    let e = b.endpoint();
    let d = b.driver();
    let engine = b.engine();
    for n in [
        m.incoming_offset as u64,
        m.outgoing_offset as u64,
        e.written,
        e.read,
        d.outbound_read,
        d.inbound_written,
        d.raw_received_packets,
        d.raw_received_bytes,
        d.raw_popped_packets,
        d.raw_popped_bytes,
        d.raw_sent_packets,
        d.raw_sent_bytes,
        d.discarded_packets,
        engine.send_admitted,
        engine.receive_consumed,
    ] {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    bytes.extend_from_slice(&[
        u8::from(m.message_available),
        u8::from(m.send_pending),
        u8::from(m.records.read_eof),
        u8::from(m.records.shutdown_started),
        u8::from(m.records.shutdown_completed),
        u8::from(m.fault.is_some()),
        u8::from(m.records.fault.is_some()),
    ]);
    hash_parts(b"l2tunnel/raw-packet-freeze-counters/v1\0", &[&bytes])
}

impl<I: PacketIo + Send + 'static> PacketCarrier<I> {
    /// Enable exact per-lane PacketIo timing once on the actual ready owner.
    /// All diagnostic backing is reserved before any lane is changed. This performs
    /// no I/O, changes no transport quota and does not renew an existing deadline.
    /// If a lane is already blocked, its earlier interval remains explicitly unknown.
    pub fn enable_send_timing(&mut self) -> Result<(), Error> {
        self.check()?;
        if !self.ready
            || self
                .lanes
                .iter()
                .flatten()
                .any(|lane| !lane.io.send_timing.is_empty())
        {
            return Err(Error::Configuration);
        }
        let mut cells = [Vec::new(), Vec::new()];
        for (index, lane) in self.lanes.iter().enumerate() {
            if lane.is_some() {
                cells[index]
                    .try_reserve_exact(1)
                    .map_err(|_| Error::Capacity)?;
            }
        }
        let now = Instant::now();
        for (lane, mut cell) in self.lanes.iter_mut().zip(cells) {
            if let Some(lane) = lane {
                cell.push(super::send_timing::SendTiming::new(
                    now,
                    lane.io.send_observations.blocked,
                ));
                lane.io.send_timing = cell;
            }
        }
        Ok(())
    }
    /// Read only bounded scalar custody. Terminal observations are frozen before release.
    /// Missing/poisoned observations never replace the original transport failure.
    pub fn buffer_snapshot(&self, now: Instant) -> BufferSnapshot {
        if let Some(snapshot) = self.terminal_buffers.first() {
            return *snapshot;
        }
        let mut snapshot = BufferSnapshot {
            captured_at: now,
            terminal: self.fault.is_some(),
            lanes: [None, None],
            unavailable_lanes: 0,
        };
        for (index, lane) in self.lanes.iter().enumerate() {
            if let Some(lane) = lane {
                match lane.buffer_snapshot(now) {
                    Ok(value) => snapshot.lanes[index] = Some(value),
                    Err(_) => snapshot.unavailable_lanes |= 1 << index,
                }
            }
        }
        snapshot
    }
    fn count(&self) -> usize {
        if self.info.duplex == Duplex::Full {
            1
        } else {
            2
        }
    }
    fn check(&self) -> Result<(), Error> {
        if let Some(e) = &self.fault {
            return Err(e.clone());
        }
        let now = Instant::now();
        // Exporter ownership is initial-only. An unactivated carrier cannot
        // keep an obsolete steady-state data/control path alive beyond setup.
        if self.final_context.is_none() && now >= self.deadline {
            return Err(Error::Expired);
        }
        if self.ready
            && self
                .lanes
                .iter()
                .flatten()
                .any(|d| now.saturating_duration_since(d.last_alive) >= Duration::from_secs(15))
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn receive_cell(&mut self, i: usize, cell: Cell) -> Result<(), Error> {
        match cell.header.kind {
            wire::Kind::Hello => {
                let bytes: [u8; wire::HELLO] = wire::array(&cell.body)?;
                let hello = wire::Hello::parse(&bytes)?;
                if hello.count != self.count()
                    || hello.pair != self.info.transcript_digest
                    || hello.armed != self.armed
                {
                    return Err(Error::Proof);
                }
                for j in 0..self.count() {
                    let lane = self.lanes[j].as_ref().ok_or(Error::Proof)?;
                    let peer = hello.lanes[j].ok_or(Error::Proof)?;
                    if let Err(error) = lane.proof.complementary(peer) {
                        // A diagnostic lock failure must not replace the original proof error.
                        if let Ok(mut state) = lane.io.state.try_lock()
                            && state.proof_failure.is_none()
                        {
                            state.proof_failure = Some(SetupProofFailure::hello(
                                SetupProofBoundary::PeerHello,
                                lane.proof,
                                peer,
                            ));
                        }
                        return Err(error);
                    }
                }
                if self.peer_hello.is_some_and(|old| old != bytes) {
                    return Err(Error::Proof);
                }
                self.peer_hello = Some(bytes);
                let lane = self.lanes[i].as_mut().ok_or(Error::Proof)?;
                lane.hello_reply |= lane.hello;
                lane.hello = true;
                let (client, server) = if self.info.is_client {
                    (&self.local_hello, &bytes)
                } else {
                    (&bytes, &self.local_hello)
                };
                self.commit_proof = Some(hash_parts(
                    b"l2tunnel/raw-packet-commit-proof/v1\0",
                    &[
                        &self.info.transcript_digest,
                        &self.policy_digest,
                        &self.armed,
                        client,
                        server,
                    ],
                ));
            }
            wire::Kind::Commit | wire::Kind::CommitAck => {
                let kind = cell.header.kind;
                if (kind == wire::Kind::Commit) == self.info.is_client {
                    return Err(Error::Proof);
                }
                let proof = self.commit_proof.ok_or(Error::Proof)?;
                if cell.body
                    != wire::commit(
                        kind,
                        self.count(),
                        proof,
                        self.info.transcript_digest,
                        self.policy_digest,
                    )
                {
                    return Err(Error::Proof);
                }
                let lane = self.lanes[i].as_mut().ok_or(Error::Proof)?;
                if kind == wire::Kind::Commit {
                    lane.commit = true;
                } else {
                    lane.ack = true;
                }
            }
            wire::Kind::Data | wire::Kind::Feedback => {
                if !self.ready {
                    self.lanes[i].as_mut().ok_or(Error::Proof)?.early = Some(cell);
                    return Ok(());
                }
                // These actual accepted records spend the peer's lane-local
                // horizon even when all upper reverse traffic uses the other
                // Half lane. Return only authenticated carrier retirement.
                let lane = self.lanes[i].as_mut().ok_or(Error::Proof)?;
                lane.retirement_required = lock(&lane.io.state)?
                    .fence
                    .as_ref()
                    .ok_or(Error::Proof)?
                    .retired;
                self.records.push_back(ReceivedRecord {
                    received_at: cell.received_at,
                    lane: if i == 0 {
                        PairLane::First
                    } else {
                        PairLane::Second
                    },
                    kind: if cell.header.kind == wire::Kind::Data {
                        RecordKind::Data
                    } else {
                        RecordKind::Feedback
                    },
                    bytes: cell.body,
                });
            }
            wire::Kind::Ping => {
                self.lanes[i].as_mut().ok_or(Error::Proof)?.pong = Some(wire::array(&cell.body)?);
            }
            wire::Kind::Pong => {
                let lane = self.lanes[i].as_mut().ok_or(Error::Proof)?;
                if lane.ping == Some(wire::array(&cell.body)?) {
                    lane.ping = None;
                    lane.last_alive = Instant::now();
                }
            }
            wire::Kind::Window => {}
        }
        Ok(())
    }
    fn turn(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.check()?;
        let count = self.count();
        let mut progress = false;
        for offset in 0..count {
            let i = (self.cursor + offset) % count;
            self.check()?;
            let lane = self.lanes[i].as_mut().ok_or(Error::Proof)?;
            if self.ready
                && self.final_context.is_none()
                && lane.pending.is_none()
                && lane
                    .retirement_required
                    .saturating_sub(lane.retirement_reported)
                    >= lane.retirement_threshold()?
            {
                // Attempt the coalesced report in this existing physical turn.
                // Do not reserve the free slot after receive: the upper owner
                // must first get its normal chance to piggyback new retirement.
                // A blocked report still retains its exact packet and nonce.
                match lane.stage(wire::Kind::Window, &[], self.transaction) {
                    Ok(()) => progress = true,
                    Err(Error::Busy) => {}
                    Err(error) => return Err(error),
                }
            }
            progress |= lane.progress()?;
            self.check()?;
            for _ in 0..(usize::from(self.policy.queue_packets) + 4) {
                let cell = {
                    let mut state = lock(&self.lanes[i].as_ref().ok_or(Error::Proof)?.io.state)?;
                    let index = state
                        .incoming
                        .iter()
                        .position(|cell| cell.final_metadata.is_none());
                    index.and_then(|index| state.incoming.remove(index))
                };
                let Some(cell) = cell else {
                    break;
                };
                self.receive_cell(i, cell)?;
                progress = true;
                self.check()?;
            }
        }
        self.cursor = (self.cursor + 1) % count;
        let all_hello = self.lanes[..count]
            .iter()
            .all(|d| d.as_ref().is_some_and(|d| d.hello && d.sent_hello));
        if all_hello {
            let proof = self.commit_proof.ok_or(Error::Proof)?;
            for lane in self.lanes.iter().flatten() {
                let mut state = lock(&lane.io.state)?;
                state.peer_hello = self.peer_hello;
                state.commit_body = Some(wire::commit(
                    wire::Kind::Commit,
                    count,
                    proof,
                    self.info.transcript_digest,
                    self.policy_digest,
                ));
                state.ack_body = Some(wire::commit(
                    wire::Kind::CommitAck,
                    count,
                    proof,
                    self.info.transcript_digest,
                    self.policy_digest,
                ));
            }
        }
        let all_commit = self.lanes[..count]
            .iter()
            .all(|d| d.as_ref().is_some_and(|d| d.commit));
        let now = Instant::now();
        for i in 0..count {
            let lane = self.lanes[i].as_mut().ok_or(Error::Proof)?;
            if self.ready && self.final_context.is_none() && lane.pending.is_none() {
                if let Some(pong) = lane.pong {
                    match lane.stage(wire::Kind::Pong, &pong, self.transaction) {
                        Ok(()) => {
                            lane.pong = None;
                            progress = true;
                        }
                        Err(Error::Busy) => {}
                        Err(e) => return Err(e),
                    }
                } else if now.saturating_duration_since(lane.last_ping) >= Duration::from_secs(5)
                    && lane.ping.is_none()
                {
                    let mut nonce = [0; 8];
                    SystemRandom::new()
                        .fill(&mut nonce)
                        .map_err(|_| Error::Proof)?;
                    match lane.stage(wire::Kind::Ping, &nonce, self.transaction) {
                        Ok(()) => {
                            lane.ping = Some(nonce);
                            lane.last_ping = now;
                            progress = true;
                        }
                        Err(Error::Busy) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            if now < self.deadline && lane.retry_due(now) {
                let Some(kind) =
                    lane.transition_kind(self.info.is_client, self.ready, all_hello, all_commit)
                else {
                    continue;
                };
                let body = match kind {
                    wire::Kind::Hello => self.local_hello.to_vec(),
                    wire::Kind::Commit | wire::Kind::CommitAck => wire::commit(
                        kind,
                        count,
                        self.commit_proof.ok_or(Error::Proof)?,
                        self.info.transcript_digest,
                        self.policy_digest,
                    )
                    .to_vec(),
                    _ => return Err(Error::Proof),
                };
                match lane.stage(kind, &body, self.transaction) {
                    Ok(()) => {
                        if kind == wire::Kind::Hello {
                            lane.hello_reply = false;
                        }
                        progress = true;
                    }
                    Err(Error::Busy) => {}
                    Err(e) => return Err(e),
                }
            }
            self.check()?;
        }
        let committed = if self.info.is_client {
            self.lanes[..count]
                .iter()
                .all(|d| d.as_ref().is_some_and(|d| d.ack))
        } else {
            all_commit
                && self.lanes[..count]
                    .iter()
                    .all(|d| d.as_ref().is_some_and(|d| d.sent_ack))
        };
        if !self.ready && committed {
            self.check()?;
            self.ready = true;
            for lane in self.lanes.iter_mut().flatten() {
                lock(&lane.io.state)?.active = true;
                lane.last_alive = Instant::now();
                lane.last_ping = Instant::now();
            }
            progress = true;
        }
        if self.ready {
            for i in 0..count {
                let early = self.lanes[i].as_mut().ok_or(Error::Proof)?.early.take();
                if let Some(cell) = early {
                    self.receive_cell(i, cell)?;
                    progress = true;
                }
            }
        }
        self.check()?;
        if self.tick.as_mut().poll(cx).is_ready() {
            self.tick
                .as_mut()
                .reset(Instant::now() + Duration::from_millis(1));
            cx.waker().wake_by_ref();
        }
        if !self.ready && self.timer.as_mut().poll(cx).is_ready() {
            return Err(Error::Expired);
        }
        Ok(progress)
    }
    fn fail(&mut self, e: Error) -> Error {
        let e = self.fault.get_or_insert(e).clone();
        if self.terminal_buffers.is_empty() {
            let now = Instant::now();
            for lane in self.lanes.iter_mut().flatten() {
                if let Some(timing) = lane.io.send_timing.first_mut() {
                    timing.terminal(now);
                }
            }
            let snapshot = self.buffer_snapshot(now);
            self.terminal_buffers.push(snapshot);
        }
        for (saved, lane) in self.terminal_sent.iter_mut().zip(&mut self.lanes) {
            if saved.is_none()
                && let Some(lane) = lane
            {
                *saved = lane.completed.take();
            }
        }
        self.lanes = [None, None];
        self.records.clear();
        e
    }
    /// Check the actual fixed active/transition lifetime without performing I/O.
    /// A terminal failure drops all original owners before returning the first cause.
    pub fn check_live(&mut self) -> Result<(), Error> {
        match self.check() {
            Ok(()) => Ok(()),
            Err(e) => Err(self.fail(e)),
        }
    }
    /// Exact immutable physical geometry checked against every occupied original.
    pub fn geometry(&self) -> Result<RecordGeometry, Error> {
        self.check()?;
        if !self.ready {
            return Err(Error::Proof);
        }
        let geometry = self.policy.record_geometry()?;
        for lane in self.lanes.iter().flatten() {
            let state = lock(&lane.io.state)?;
            if state.config.mtu != geometry.path_mtu || state.policy != self.policy {
                return Err(Error::Proof);
            }
        }
        if self.lanes.iter().flatten().count() != self.count() {
            return Err(Error::Proof);
        }
        Ok(geometry)
    }
    /// Actual immutable authenticated packet policy, without any transfer authority.
    pub fn policy(&self) -> PacketPolicy {
        self.policy
    }
    /// Actual complete policy commitment accepted by the original raw transition.
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    /// Exact occupied original tuples in First/Second order, with no dummy lane.
    pub fn lane_endpoints(
        &self,
    ) -> Result<[Option<(std::net::SocketAddr, std::net::SocketAddr)>; 2], Error> {
        self.geometry()?;
        let mut result = [None, None];
        for (target, lane) in result.iter_mut().zip(&self.lanes) {
            if let Some(lane) = lane {
                let state = lock(&lane.io.state)?;
                *target = Some((state.config.local.into(), state.config.peer.into()));
            }
        }
        Ok(result)
    }
    /// Actual immutable per-lane byte capacities, without polling or changing credit.
    pub fn lane_limits(&self) -> Result<[Option<LaneLimits>; 2], Error> {
        self.geometry()?;
        let maximum = u64::from(self.policy.mtu)
            .checked_sub(40)
            .ok_or(Error::Proof)?;
        let data_reserve_bytes = compact::FinalKind::Data
            .reserve()
            .checked_mul(maximum)
            .ok_or(Error::Exhausted)?;
        let mut result = [None, None];
        for (target, lane) in result.iter_mut().zip(&self.lanes) {
            if let Some(lane) = lane {
                let state = lock(&lane.io.state)?;
                let fence = state.fence.as_ref().ok_or(Error::Proof)?;
                *target = Some(LaneLimits {
                    local_horizon_bytes: fence.local_horizon,
                    peer_horizon_bytes: fence.peer_horizon,
                    data_reserve_bytes,
                    send_data_capacity_bytes: fence
                        .peer_horizon
                        .checked_sub(data_reserve_bytes)
                        .ok_or(Error::Proof)?,
                    receive_data_capacity_bytes: fence
                        .local_horizon
                        .checked_sub(data_reserve_bytes)
                        .ok_or(Error::Proof)?,
                });
            }
        }
        Ok(result)
    }
    /// Number of actual occupied original owners; never a synthetic duplex width.
    pub fn lane_count(&self) -> usize {
        self.count()
    }
    /// Actual retained receive bitmap bytes across the original occupied lanes.
    /// Other nested transport allocations remain a separate resource inventory.
    pub fn receive_range_capacity_bytes(&self) -> Result<usize, Error> {
        self.lanes.iter().flatten().try_fold(0usize, |total, lane| {
            total
                .checked_add(lock(&lane.io.state)?.range_capacity_bytes())
                .ok_or(Error::Capacity)
        })
    }
    /// Actual preallocated storage for the single frozen terminal scalar snapshot.
    /// This remains retained after the original lanes are released.
    pub fn terminal_snapshot_capacity_bytes(&self) -> usize {
        self.terminal_buffers.capacity() * std::mem::size_of::<BufferSnapshot>()
    }
    /// Original setup cap; observing it never grants another setup interval.
    pub fn setup_deadline(&self) -> Instant {
        self.deadline
    }
    /// Existing physical-service, transition and liveness wakes; no new timer owner.
    pub fn next_wake(&self) -> Result<Instant, Error> {
        self.check()?;
        let mut wake = self.tick.deadline();
        if !self.ready {
            wake = wake.min(self.timer.deadline());
        }
        let count = self.count();
        let all_hello = self.lanes[..count].iter().all(|lane| {
            lane.as_ref()
                .is_some_and(|lane| lane.hello && lane.sent_hello)
        });
        let all_commit = self.lanes[..count]
            .iter()
            .all(|lane| lane.as_ref().is_some_and(|lane| lane.commit));
        for lane in self.lanes.iter().flatten() {
            if self.ready {
                wake = wake.min(
                    lane.last_alive
                        .checked_add(Duration::from_secs(15))
                        .ok_or(Error::Exhausted)?,
                );
                let retry_ready = self.final_context.is_some()
                    && lane.pending.is_none()
                    && !lane.io.pending()
                    && lane.final_prepared.is_none()
                    && lane.tracked.is_none()
                    && lane.completed.is_none();
                if lane.ping.is_none() || retry_ready {
                    let interval = if self.final_context.is_some() && lane.ping.is_some() {
                        TRANSITION_RETRY_INTERVAL
                    } else {
                        Duration::from_secs(5)
                    };
                    wake = wake.min(
                        lane.last_ping
                            .checked_add(interval)
                            .ok_or(Error::Exhausted)?,
                    );
                }
            } else if lane.pending.is_none()
                && lane
                    .transition_kind(self.info.is_client, self.ready, all_hello, all_commit)
                    .is_some()
                && let Some(last) = lane.last_transition
            {
                // Reserved attempts waiting for a peer prerequisite must not
                // advertise an already elapsed Hello retry as an immediate wake.
                wake = wake.min(
                    last.checked_add(TRANSITION_RETRY_INTERVAL)
                        .ok_or(Error::Exhausted)?,
                );
            }
        }
        Ok(wake)
    }
    /// Maximum complete upper recovery record under the authenticated packet policy.
    pub fn max_record_bytes(&self) -> usize {
        self.policy.body_limit()
    }
    /// Actual accepted pair metadata; it contains no keys or handoff capability.
    pub fn info(&self) -> &PairInfo {
        &self.info
    }
    /// Copy one initial Noise/member setup record into the finite carrier slot.
    /// This exporter-protected path ends at the original setup deadline and is
    /// unavailable after final Records activation. User traffic uses final Records.
    pub fn stage_setup_record(
        &mut self,
        lane: PairLane,
        kind: RecordKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.check_live()?;
        if self.final_context.is_some() {
            return Err(Error::Configuration);
        }
        if Instant::now() >= self.deadline {
            return Err(self.fail(Error::Expired));
        }
        self.stage_bootstrap_inner(lane, kind, bytes)
    }
    fn stage_bootstrap_inner(
        &mut self,
        lane: PairLane,
        kind: RecordKind,
        bytes: &[u8],
    ) -> Result<(), Error> {
        if let Err(e) = self.check() {
            return Err(self.fail(e));
        }
        let i = lane.index();
        if i >= self.count() || bytes.is_empty() || bytes.len() > self.policy.body_limit() {
            return Err(Error::Configuration);
        }
        if kind == RecordKind::Data && self.count() == 2 && (i == 0) != self.info.is_client {
            return Err(Error::Configuration);
        }
        let wire_kind = if kind == RecordKind::Data {
            wire::Kind::Data
        } else {
            wire::Kind::Feedback
        };
        match self.lanes[i]
            .as_mut()
            .ok_or(Error::Proof)?
            .stage(wire_kind, bytes, self.transaction)
        {
            Err(Error::Busy) => Err(Error::Busy),
            Err(e) => Err(self.fail(e)),
            Ok(()) => Ok(()),
        }
    }
    /// Reserve a bounded completion cell and stage one exact initial setup record.
    /// A successful return is admission only; consume its actual send receipt.
    pub fn stage_setup_record_tracked(
        &mut self,
        lane: PairLane,
        kind: RecordKind,
        bytes: &[u8],
    ) -> Result<RecordToken, Error> {
        self.check_live()?;
        let index = lane.index();
        let owner = self
            .lanes
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Configuration)?;
        if owner.completed.is_some() || owner.tracked.is_some() {
            return Err(Error::Busy);
        }
        self.stage_setup_record(lane, kind, bytes)?;
        let owner = self.lanes[index].as_mut().ok_or(Error::Proof)?;
        let token = RecordToken(owner.pending.as_ref().ok_or(Error::Proof)?.end);
        owner.tracked = Some(token);
        Ok(token)
    }
    /// Take one pre-reserved successful handoff receipt without renewing any age.
    pub fn take_sent_record(&mut self, lane: PairLane) -> Result<Option<SentRecord>, Error> {
        self.check_live()?;
        Ok(self
            .lanes
            .get_mut(lane.index())
            .and_then(Option::as_mut)
            .ok_or(Error::Configuration)?
            .completed
            .take())
    }
    /// Observe one real physical handoff even after expiry released original I/O.
    /// No I/O is performed. A returned failure remains terminal and never changes
    /// the original sent_at, grants peer-delivery credit or permits retransmission.
    pub fn take_sent_record_observed(
        &mut self,
        lane: PairLane,
    ) -> Result<SentRecordObservation, Error> {
        let index = lane.index();
        if index >= self.count() {
            return Err(Error::Configuration);
        }
        let failure = self.check_live().err();
        let sent = match self.terminal_sent[index].take() {
            Some(sent) => Some(sent),
            None => self.lanes[index]
                .as_mut()
                .and_then(|owner| owner.completed.take()),
        };
        Ok(SentRecordObservation { sent, failure })
    }
    /// Bounded fair physical progress, transition replies and authenticated liveness.
    pub fn poll_progress(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Err(e) = lock(&self.budget).map(|mut b| b.quota = 32) {
            return Poll::Ready(Err(self.fail(e)));
        }
        self.poll_progress_remaining(cx)
    }
    /// Continue this physical work turn without replenishing its original quota.
    /// A runtime may use remaining work after committing fresh output following
    /// its initial receipt poll. Pacing, lane fairness and deadlines are unchanged.
    pub fn poll_progress_remaining(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.turn(cx) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(e) => Poll::Ready(Err(self.fail(e))),
        }
    }
    /// Borrow the oldest locally committed authenticated recovery record.
    pub fn record(&self) -> Option<&ReceivedRecord> {
        if self.check().is_ok() {
            self.records.front()
        } else {
            None
        }
    }
    /// Earliest already authenticated upper-record arrival still owned locally.
    /// Includes bounded lane cells not yet exposed by fair progress. This is not
    /// a timestamp for unread kernel/network input and performs no I/O.
    pub fn earliest_authenticated_record_at(&self) -> Result<Option<Instant>, Error> {
        let mut earliest = self.records.iter().map(|r| r.received_at).min();
        for lane in self.lanes.iter().flatten() {
            if let Some(cell) = &lane.early
                && matches!(cell.header.kind, wire::Kind::Data | wire::Kind::Feedback)
            {
                earliest = Some(earliest.map_or(cell.received_at, |old| old.min(cell.received_at)));
            }
            let state = lock(&lane.io.state)?;
            if let Some(at) = state.earliest_authenticated_upper_at() {
                earliest = Some(earliest.map_or(at, |old| old.min(at)));
            }
        }
        Ok(earliest)
    }

    /// Release one local carrier delivery cell, never native delivery credit.
    pub fn consume_record(&mut self) -> Result<(), Error> {
        if let Err(e) = self.check() {
            return Err(self.fail(e));
        }
        let record = self.records.pop_front().ok_or(Error::Busy)?;
        let state = &self.lanes[record.lane.index()]
            .as_ref()
            .ok_or(Error::Proof)?
            .io
            .state;
        let mut state = lock(state)?;
        state.records_outstanding = state
            .records_outstanding
            .checked_sub(1)
            .ok_or(Error::Proof)?;
        Ok(())
    }
    /// Drop all originals without polling a TCP shutdown or claiming a clean close.
    pub fn abort(mut self) {
        for lane in self.lanes.iter_mut().flatten() {
            if let Some(timing) = lane.io.send_timing.first_mut() {
                timing.terminal(Instant::now());
            }
        }
        self.lanes = [None, None];
        self.records.clear();
    }
}

#[cfg(test)]
#[path = "transaction_tests.rs"]
mod tests;

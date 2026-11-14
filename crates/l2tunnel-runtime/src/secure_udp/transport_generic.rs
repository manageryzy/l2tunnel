//! Explicit generic construction and observation, sharing the sole runtime owner.

use super::generic_actions::ActionWork;
use super::*;
use l2tunnel::swift_configuration::Configuration as C;
use l2tunnel_swift::storage;

type StateObservation = (
    core::Epoch,
    transaction::Phase,
    Option<transaction::Operation>,
    Scope,
);

/// Actual generic transaction state, separate from legacy Swift policy status.
#[derive(Clone, Debug)]
pub struct TransactionSnapshot {
    /// True only after the sole native runtime publishes readiness.
    pub running: bool,
    /// Injected microseconds since the original driver origin.
    pub elapsed_micros: u64,
    /// Actual completed membership and original connected endpoints.
    pub info: member::Info,
    /// Fixed authenticated setup and Control digest H0.
    pub configuration: security::ConfigDigest,
    /// User scope currently installed for physical native admission/completion.
    pub physical_scope: Scope,
    /// Complete configuration of the actual current reserved engine generation.
    pub current: C,
    /// Exact locally requested configuration retained through negotiated completion.
    pub requested: Option<C>,
    /// Actual leased operation identity and original cap, when retained.
    pub operation: Option<transaction::Operation>,
    /// Actual current reserved engine epoch.
    pub epoch: core::Epoch,
    /// Actual leased management peer phase, without a second status machine.
    pub phase: transaction::Phase,
    /// Actual Bank charges; external capacity is an explicitly partial subtotal.
    pub storage: storage::Usage,
    /// False until all Control/Peer and remaining runtime storage is reserved.
    pub resource_preallocation_complete: bool,
    /// Actual physically installed local outgoing policy.
    pub send: policy::Direction,
    /// Actual physically installed local incoming policy.
    pub receive: policy::Direction,
    /// Actual current engine observations, without copying its mutable owner.
    pub swift: records::Stats,
    /// Actual current engine's unconfirmed recovery sources.
    pub swift_unconfirmed: usize,
    /// Bounded actual current per-channel observations.
    pub channels: Vec<records::ChannelStats>,
    /// Sole-loop scheduling, wire credit and native-pressure observations.
    pub performance: Performance,
    /// Actual fixed Control retained custody.
    pub control: recovery::Retained,
    /// Actual common security, wire and physical native observations.
    pub counters: Counters,
    /// Actual fixed-scope authenticated challenge observations.
    pub liveness: Liveness,
    /// Original bounded terminal category, absent while running.
    pub terminal: Option<StopReason>,
}

/// Explicit generic local termination; no peer-confirmed clean close is implied.
#[derive(Clone, Debug)]
pub struct TransactionStopped {
    /// Original local termination category.
    pub reason: StopReason,
    /// Final actual generic observation.
    pub snapshot: TransactionSnapshot,
}

pub(super) type TransactionReply = oneshot::Sender<Result<core::Epoch, SwitchError>>;

/// Shared producer of complete supported generic configurations.
#[derive(Clone)]
pub struct TransactionControlHandle(mpsc::Sender<(C, TransactionReply)>);

/// Unique bounded complete-configuration request receiver.
pub struct TransactionControlRequests(pub(super) mpsc::Receiver<(C, TransactionReply)>);

/// Allocate exactly one queued request; dropping a waiter never cancels custody.
pub fn transaction_channel() -> (TransactionControlHandle, TransactionControlRequests) {
    let (sender, receiver) = mpsc::channel(1);
    (
        TransactionControlHandle(sender),
        TransactionControlRequests(receiver),
    )
}

impl TransactionControlHandle {
    /// Wait for actual negotiated completion of one complete supported value.
    pub async fn switch(&self, configuration: C) -> Result<core::Epoch, SwitchError> {
        let (sender, receiver) = oneshot::channel();
        self.0
            .try_send((configuration, sender))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SwitchError::Busy,
                mpsc::error::TrySendError::Closed(_) => SwitchError::Closed,
            })?;
        receiver.await.unwrap_or(Err(SwitchError::Closed))
    }
}

pub(super) struct PendingRequest {
    pub(super) configuration: C,
    pub(super) cap: transaction::Tick,
    pub(super) reply: TransactionReply,
}

pub(super) struct Runtime {
    pub(super) contract: TransactionContract,
    pub(super) action: Option<ActionWork>,
    pub(super) request: Option<PendingRequest>,
    pub(super) cursor: bool,
    pub(super) outcome: Option<transactions::Outcome>,
    pub(super) completion: Option<(TransactionReply, Result<core::Epoch, SwitchError>)>,
    pub(super) observation_dirty: bool,
}

impl Driver {
    pub(super) fn transaction_observation(&self) -> io::Result<Option<StateObservation>> {
        let owner::DataOwner::Generic(state) = &self.owner else {
            return Ok(None);
        };
        Ok(Some((
            state.epoch(),
            state.peer().phase(),
            state.peer().operation(),
            self.feedback_scope,
        )))
    }

    pub(super) fn new_transaction(
        parts: member::Parts,
        contract: TransactionContract,
        origin: Instant,
    ) -> io::Result<(tokio::net::UdpSocket, Self)> {
        if origin >= parts.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original setup deadline before generic readiness",
            ));
        }
        let expected = contract.expected_configuration();
        let local = parts.socket.local_addr()?;
        let remote = parts.socket.peer_addr()?;
        if parts.info.authenticated.configuration != expected.0
            || parts.info.binding != parts.root.binding()
            || parts.info.role != parts.root.role()
            || parts.info.role != contract.role()
            || parts.info.authenticated.session != parts.info.binding.session
            || local != parts.info.local_addr
            || remote != parts.info.peer_addr
            || local.is_ipv6() != contract.ipv6()
            || remote.is_ipv6() != contract.ipv6()
            || parts.cover != contract.cover()
        {
            return Err(invalid(
                "generic contract differs from actual authenticated session/role/path/cover",
            ));
        }
        let config = contract.resolve(contract.initial())?;
        if config != contract.config() {
            return Err(invalid(
                "generic initial configuration differs from runtime template",
            ));
        }
        config.validate_cover(parts.cover, contract.ipv6())?;
        let selected = config
            .streams
            .ok_or_else(|| invalid("generic construction requires selected streams"))?;
        let ip = if contract.ipv6() { 48 } else { 28 };
        let control_scope = Scope {
            epoch: config.control_epoch,
            configuration: expected,
        };
        let data_scope = Scope {
            epoch: config.data_epoch,
            configuration: security::ConfigDigest(contract.data_digest().0),
        };
        let role = if parts.info.role == security::Role::Initiator {
            mg::Role::Client
        } else {
            mg::Role::Server
        };
        let identity = transaction::Identity {
            session: mg::SessionId(parts.info.binding.session.0),
            role,
            local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
            remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
            lane: mg::LaneId(LANE),
        };
        let records = record::Records::new(
            parts.root,
            security::LaneId(LANE),
            config.security,
            security::Protection::ChaCha20Poly1305,
            parts.cover,
            control_scope,
            data_scope,
        )
        .map_err(invalid)?;
        let arq_plan = |index: usize| {
            recovery::storage::Plan::for_arq(selected.streams[index].delivery.recovery)
                .map_err(invalid)
        };
        let arq_plans = [arq_plan(0)?, arq_plan(1)?, arq_plan(2)?];
        let arq_capacity = arq_plans.iter().try_fold(0usize, |total, plan| {
            total
                .checked_add(plan.capacity_bytes())
                .ok_or_else(|| invalid("reserved control recovery layout overflow"))
        })?;
        if arq_capacity > contract.settings().retained_bytes {
            return Err(invalid("control recovery exceeds generic retained budget"));
        }
        let control = control_owner::Owner::new_leased_reserved_arq(
            config.control,
            selected,
            delivery::Binding {
                session: identity.session,
                lane: identity.lane,
                local_role: role,
                control_epoch: config.control_epoch.0,
            },
            envelope_scope(control_scope),
            envelope_scope(data_scope),
            Duration::ZERO,
            config.lifetime.lease,
            arq_plans.map(|plan| recovery::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            }),
        )
        .map_err(invalid)?;
        let actual_arq = control
            .arq_storage_usage()
            .ok_or_else(|| protocol("generic control recovery is not reserved"))?;
        let mut actual_arq_capacity = 0usize;
        for (usage, plan) in actual_arq.iter().zip(arq_plans) {
            if usage.capacity_bytes != plan.capacity_bytes() {
                return Err(protocol("actual control recovery differs from its plan"));
            }
            actual_arq_capacity = actual_arq_capacity
                .checked_add(usage.capacity_bytes)
                .ok_or_else(|| invalid("actual control recovery layout overflow"))?;
        }
        let capacity = records
            .capacity(config.security.max_body_bytes)
            .map_err(invalid)?;
        let control_message = selected
            .streams
            .iter()
            .map(|settings| settings.max_message_bytes)
            .max()
            .ok_or_else(|| invalid("generic streams have no message storage"))?;
        let buffers = buffers::Buffers::new(
            parts.cover.limits().max_packet_bytes,
            capacity
                .seal_workspace_bytes
                .max(capacity.open_workspace_bytes),
            config.security.max_body_bytes,
            control.max_packet_bytes(),
            control_message,
            swift::control::MAX_FRAME,
        )?;
        let native = native_storage::Queue::new(
            config.native.pending_packets,
            config.native.pending_bytes,
            config.receive.records.max_native,
        )?;
        let inputs = buffers::Inputs::new(
            READ_BUFFER_BYTES,
            parts
                .cover
                .limits()
                .max_packet_bytes
                .checked_add(1)
                .ok_or_else(exhausted)?,
        )?;
        let input_capacity = inputs.capacity_bytes();
        // Set already charges its own embedded layout. This known subtotal does
        // not claim complete Control/Peer/catalog preallocation.
        let external = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<transactions::State>())
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<storage::Set>()))
            .and_then(|bytes| bytes.checked_add(native.capacity_bytes()))
            .and_then(|bytes| bytes.checked_add(buffers.capacity_bytes()))
            .and_then(|bytes| bytes.checked_add(input_capacity))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<buffers::Inputs>()))
            .and_then(|bytes| bytes.checked_add(actual_arq_capacity))
            .ok_or_else(|| invalid("known generic runtime storage layout overflow"))?;
        let bank = engines::Bank::new(
            identity,
            core::Epoch(config.data_epoch.0),
            contract.initial(),
            storage::Limits {
                capacity_bytes: contract.settings().retained_bytes,
            },
            external,
        )?;
        let state = transactions::State::new(
            identity,
            core::Epoch(config.data_epoch.0),
            contract.envelope(),
            contract.catalog().clone(),
            contract.settings(),
            control.transaction_binding()?,
            Duration::ZERO,
            config.lifetime.lease,
            bank,
        )?;
        let wrapper = config
            .control
            .wire_overhead
            .checked_add(config.control_wrapper_bytes())
            .ok_or_else(exhausted)?;
        let reserve = wrapper
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(config.control.recovery.max_source_bytes))
            .and_then(|bytes| bytes.checked_add(recovery::DATA_HEADER_BYTES))
            .and_then(|bytes| bytes.checked_add(recovery::ACK_PACKET_BYTES))
            .ok_or_else(exhausted)?;
        let lease = add(0, config.lifetime.lease)?;
        origin
            .checked_add(config.lifetime.lease)
            .ok_or_else(|| invalid("generic lease exceeds runtime clock"))?;
        let next_report = config
            .report_interval
            .map(|interval| add(0, interval))
            .transpose()?;
        Ok((
            parts.socket,
            Self {
                config,
                info: parts.info,
                cover: parts.cover,
                origin,
                bootstrap: parts.bootstrap,
                joining: parts.joining,
                outer: parts.next_outer,
                records,
                owner: owner::DataOwner::Generic(owner::ReservedState::new(state)?),
                generic: Some(Runtime {
                    contract,
                    action: None,
                    request: None,
                    cursor: false,
                    outcome: None,
                    completion: None,
                    observation_dirty: false,
                }),
                send: config.send,
                receive: config.receive,
                source_scope: data_scope,
                feedback_scope: data_scope,
                target: None,
                transaction_origin: None,
                resolved: None,
                control,
                policy_source: None,
                policy_cap: None,
                pending_outcome: None,
                control_work: false,
                waiting: None,
                buffers,
                inputs: Some(inputs),
                envelope_rx: 1,
                native,
                written: NativeWritten::new(
                    NativeOrigin::new(&parts.info, data_scope, records::Direction::Receive),
                    config.receive.records.channels,
                )?,
                retired_send: None,
                retired_receive: None,
                bucket: Bucket::new(config.send.bytes_per_second, config.wire.burst_bytes),
                reserve,
                ip,
                ingress: IngressBudget {
                    left: config.work.receive_packets,
                    refill: add(0, config.work.receive_interval)?,
                },
                counters: Counters {
                    loop_input_capacity_bytes: input_capacity,
                    ..Counters::default()
                },
                performance: performance::State::default(),
                live: Liveness::default(),
                challenge: None,
                pong: None,
                pong_deadline: None,
                remote_ping: 0,
                next_nonce: 1,
                next_ping: add(0, config.lifetime.ping_interval)?,
                lease,
                next_report,
                terminal: None,
            },
        ))
    }

    pub(super) fn snapshot_transaction(
        &self,
        now: u64,
        running: bool,
    ) -> io::Result<TransactionSnapshot> {
        let owner::DataOwner::Generic(state) = &self.owner else {
            return Err(protocol(
                "generic snapshot requested from legacy data owner",
            ));
        };
        let runtime = self
            .generic
            .as_ref()
            .ok_or_else(|| protocol("generic owner missing actual runtime contract"))?;
        let engine = state.engine(state.epoch())?;
        let mut counters = self.counters;
        counters.native_pending_packets = self.native.len();
        counters.native_pending_bytes = self.native.bytes();
        counters.native_storage_capacity_bytes = self.native.capacity_bytes();
        counters.workspace_capacity_bytes = self.buffers.capacity_bytes();
        Ok(TransactionSnapshot {
            running,
            elapsed_micros: now,
            info: self.info,
            configuration: runtime.contract.expected_configuration(),
            physical_scope: self.source_scope,
            current: *state.current(),
            requested: runtime
                .request
                .as_ref()
                .map(|request| request.configuration),
            operation: state.peer().operation(),
            epoch: state.epoch(),
            phase: state.peer().phase(),
            storage: state.usage(),
            resource_preallocation_complete: false,
            send: self.send,
            receive: self.receive,
            swift: engine.stats(),
            swift_unconfirmed: engine.unconfirmed(),
            channels: (0..self
                .send
                .records
                .channels
                .max(self.receive.records.channels))
                .filter_map(|index| engine.channel_stats(index))
                .collect(),
            performance: self.performance.snapshot(now, &self.bucket),
            control: self.control.retained(),
            counters,
            liveness: self.live,
            terminal: self.terminal,
        })
    }
}

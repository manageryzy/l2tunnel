//! Explicit generic construction and observation, sharing the sole runtime owner.

use super::common_actions::ActionWork;
use super::*;
use l2tunnel::record_configuration::Configuration as C;
use l2tunnel::{record_bank::storage, record_engine as engine};

#[path = "transport_common_managed.rs"]
mod managed;
#[path = "transport_common_provision.rs"]
mod provision;
pub use managed::run_common_on_carrier;

/// Observed recovery of the same connected UDP flow, not peer-state reconciliation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SameFlowRecovery {
    /// New local ingress/proposals are paused until fresh authenticated input.
    pub unavailable: bool,
    /// Actual selected pre-accept User send failures, including failed retries.
    pub send_failures: u64,
    /// Actual User send attempts while the path was already unavailable.
    pub retry_attempts: u64,
    /// Unavailable paths restored by fresh same-session protected input.
    pub resumptions: u64,
    /// Last selected local pre-accept send failure, never peer-supplied text.
    pub last_error: Option<io::ErrorKind>,
    /// Earliest next retained User attempt on the original driver clock.
    pub retry_at_micros: Option<u64>,
}

/// Actual generic transaction state, separate from legacy Swift policy status.
#[derive(Clone, Debug)]
pub struct CommonSnapshot {
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
    /// Actual current common record owner observations.
    pub engine: engine::Statistics,
    /// Actual local full-wire byte rate.
    pub send_rate: u64,
    /// Actual remote full-wire byte rate.
    pub receive_rate: u64,
    /// Actual local sending width.
    pub send_channels: u16,
    /// Actual local receiving width.
    pub receive_channels: u16,
    /// Actual independent directional work cap, at most four schedulers per turn.
    pub rolling_work: Option<l2tunnel_fec::rolling::WorkBudget>,
    /// Actual sending and receiving rolling scheduler steps since construction.
    pub rolling_scheduler_steps: u64,
    /// Actual cumulative GF, copy and metadata work, respectively.
    pub rolling_work_used: [u64; 3],
    /// Sole-loop scheduling, wire credit and native-pressure observations.
    pub performance: Performance,
    /// Actual fixed Control retained custody.
    pub control: recovery::Retained,
    /// Actual common security, wire and physical native observations.
    pub counters: Counters,
    /// Actual fixed-scope authenticated challenge observations.
    pub liveness: Liveness,
    /// Actual same-flow retry state; no replacement socket/session is implied.
    pub path_recovery: SameFlowRecovery,
    /// Original bounded terminal category, absent while running.
    pub terminal: Option<StopReason>,
}

/// Explicit generic local termination; no peer-confirmed clean close is implied.
#[derive(Clone, Debug)]
pub struct CommonStopped {
    /// Original local termination category.
    pub reason: StopReason,
    /// Final actual generic observation.
    pub snapshot: CommonSnapshot,
}

pub(super) type TransactionReply = oneshot::Sender<Result<core::Epoch, SwitchError>>;

/// Shared producer of complete supported generic configurations.
#[derive(Clone)]
pub struct CommonControlHandle(mpsc::Sender<(C, TransactionReply)>);

/// Unique bounded complete-configuration request receiver.
pub struct CommonControlRequests(pub(super) mpsc::Receiver<(C, TransactionReply)>);

/// Allocate exactly one queued request; dropping a waiter never cancels custody.
pub fn common_channel() -> (CommonControlHandle, CommonControlRequests) {
    let (sender, receiver) = mpsc::channel(1);
    (CommonControlHandle(sender), CommonControlRequests(receiver))
}

impl CommonControlHandle {
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

#[derive(Debug, Eq, PartialEq)]
pub(super) struct PendingWire {
    pub(super) scope: Scope,
    pub(super) sealed: record::Sealed,
    pub(super) cost: usize,
    pub(super) deadline: u64,
    pub(super) carrier: Option<l2tunnel::record_bank::CarrierOutputToken>,
}
pub(super) struct Runtime {
    pub(super) contract: CommonTransactionContract,
    pub(super) action: Option<ActionWork>,
    pub(super) request: Option<PendingRequest>,
    pub(super) cursor: bool,
    pub(super) native_work: [usize; 2],
    pub(super) sealed: Option<PendingWire>,
    pub(super) wire: Vec<u8>,
    pub(super) outcome: Option<transactions::Outcome>,
    pub(super) completion: Option<(TransactionReply, Result<core::Epoch, SwitchError>)>,
    pub(super) observation_dirty: bool,
    pub(super) witnesses: Vec<l2tunnel_codec::aligned_receiver::UnitWitness>,
    pub(super) sent: Option<super::common_actions::Boundary>,
    pub(super) delivered: Option<super::common_actions::Boundary>,
    pub(super) rolling_scheduler_steps: u64,
    pub(super) rolling_work_used: [u64; 3],
    pub(super) path: SameFlowRecovery,
}

/// Run actual common record generations on the original authenticated UDP socket.
///
/// Calling this entry point checks the actual device and connected socket and
/// fallibly constructs its sole runtime owner before returning the future. It
/// starts no task or I/O loop. Construction errors are returned when the future
/// is awaited. The original Parts setup deadline is checked before and after
/// construction and again before readiness; delaying the first poll cannot renew it.
pub fn run_common<D>(
    device: D,
    parts: member::Parts,
    contract: CommonTransactionContract,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    observe: impl FnMut(&CommonSnapshot) + Send,
) -> impl Future<Output = io::Result<CommonStopped>> + Send
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    // This is actual ownership, not a copied Driver or a future-only box: the
    // same initialized security, Bank, socket and native owners enter the loop.
    run_prepared_common(
        prepare_common_runtime(device, parts, contract),
        requests,
        shutdown,
        observe,
    )
}

async fn run_prepared_common<D>(
    prepared: io::Result<PreparedRuntime<D>>,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    mut observe: impl FnMut(&CommonSnapshot) + Send,
) -> io::Result<CommonStopped>
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    let PreparedRuntime {
        device,
        socket,
        mut driver,
        setup_deadline,
    } = prepared?;
    match run_driver_clock(
        device,
        socket,
        &mut driver,
        setup_deadline,
        Requests::Common(requests),
        None,
        shutdown,
        move |driver, now, running| {
            observe(&driver.snapshot_common(now, running)?);
            Ok(())
        },
        Instant::now,
    )
    .await?
    {
        SelectedStopped::Common(stopped) => Ok(stopped),
        _ => Err(protocol("common loop returned another backend")),
    }
}

struct PreparedRuntime<D> {
    device: D,
    socket: carrier::IoOwner,
    driver: owner::StateCell<Driver>,
    setup_deadline: Instant,
}

// Complete construction before any loop Future is polled. Boxing only a Future
// would retain the constructors' debug scratch frames on the readiness poll stack.
#[inline(never)]
fn prepare_common_runtime<D>(
    device: D,
    parts: member::Parts,
    contract: CommonTransactionContract,
) -> io::Result<PreparedRuntime<D>>
where
    D: PacketDevice<Error = io::Error> + AsRawFd + Send,
{
    if device.layer() != contract.native_layer() {
        return Err(invalid(
            "authenticated native layer differs from actual device",
        ));
    }
    let setup_deadline = parts.deadline;
    let origin = Instant::now();
    if origin >= setup_deadline {
        return Err(common_setup_expired());
    }
    let (socket, driver) = Driver::new_common(parts, contract, origin)?;
    let driver = owner::StateCell::new(driver)?;
    if Instant::now() >= setup_deadline {
        return Err(common_setup_expired());
    }
    Ok(PreparedRuntime {
        device,
        socket: socket.into(),
        driver,
        setup_deadline,
    })
}

fn common_setup_expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "original setup deadline before native readiness",
    )
}

// The retained State and Bank cells remain fallible and precharged. Their
// constructors run before the service starts polling the sole I/O continuation.
#[inline(never)]
fn reserve_common_state(
    contract: &CommonTransactionContract,
    identity: transaction::Identity,
    transaction_binding: delivery::Binding,
    external: usize,
) -> io::Result<owner::ReservedCommonState> {
    let config = contract.resources();
    let bank = common_engines::Bank::new(
        identity,
        core::Epoch(config.data_epoch.0),
        contract.initial(),
        contract.geometry(),
        contract.native_limits()?,
        storage::Limits {
            capacity_bytes: contract.settings().retained_bytes,
        },
        external,
    )?;
    let state = transactions::CommonState::new(
        identity,
        core::Epoch(config.data_epoch.0),
        contract.envelope(),
        contract.catalog().clone(),
        contract.settings(),
        transaction_binding,
        Duration::ZERO,
        config.lifetime.lease,
        bank,
    )?;
    owner::ReservedCommonState::new(state)
}

// Only actual accepted membership handoffs enter this shared constructor.
struct CommonInput {
    material: establish::InitialMaterial,
    cover: cover::Config,
    bootstrap: establish::BootstrapTail,
    joining: member::JoiningTail,
    next_outer: u32,
    info: member::Info,
    deadline: Instant,
    addresses: (std::net::SocketAddr, std::net::SocketAddr),
    io_capacity: usize,
}

impl Driver {
    pub(super) fn new_common(
        parts: member::Parts,
        contract: CommonTransactionContract,
        origin: Instant,
    ) -> io::Result<(tokio::net::UdpSocket, Self)> {
        if contract.refresh_selection().is_some() || contract.extra_wire_bytes() != 0 {
            return Err(invalid("legacy Common requires unselected legacy contract"));
        }
        contract.validate_outer(None)?;
        let addresses = (parts.socket.local_addr()?, parts.socket.peer_addr()?);
        let input = CommonInput {
            material: establish::InitialMaterial::Legacy(parts.root),
            cover: parts.cover,
            bootstrap: parts.bootstrap,
            joining: parts.joining,
            next_outer: parts.next_outer,
            info: parts.info,
            deadline: parts.deadline,
            addresses,
            io_capacity: 0,
        };
        Self::new_common_input(input, contract, origin, parts.socket, |socket, driver| {
            Ok((socket, driver))
        })
    }

    fn new_common_input<S, T>(
        input: CommonInput,
        contract: CommonTransactionContract,
        origin: Instant,
        companion: S,
        finish: impl FnOnce(S, Self) -> io::Result<T>,
    ) -> io::Result<T> {
        if Instant::now() >= input.deadline || origin >= input.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original setup deadline before generic readiness",
            ));
        }
        let expected = contract.expected_configuration();
        let (local, remote) = input.addresses;
        if input.info.authenticated.configuration != expected.0
            || input.info.binding != input.material.binding()
            || input.info.role != input.material.role()
            || input.info.role != contract.role()
            || input.info.authenticated.session != input.info.binding.session
            || local != input.info.local_addr
            || remote != input.info.peer_addr
            || local.is_ipv6() != contract.ipv6()
            || remote.is_ipv6() != contract.ipv6()
            || input.cover != contract.cover()
        {
            return Err(invalid(
                "generic contract differs from actual authenticated session/role/path/cover",
            ));
        }
        contract.resolve(contract.initial())?;
        let config = contract.resources();
        let ip = (if contract.ipv6() { 48usize } else { 28usize })
            .checked_add(contract.extra_wire_bytes())
            .ok_or_else(exhausted)?;
        let control_scope = contract.fixed_control_scope().unwrap_or(Scope {
            epoch: config.control_epoch,
            configuration: expected,
        });
        let data_scope = Scope {
            epoch: config.data_epoch,
            configuration: security::ConfigDigest(contract.data_digest().0),
        };
        let role = if input.info.role == security::Role::Initiator {
            mg::Role::Client
        } else {
            mg::Role::Server
        };
        let identity = transaction::Identity {
            session: mg::SessionId(input.info.binding.session.0),
            role,
            local: mg::EndpointId(if role == mg::Role::Client { 1 } else { 2 }),
            remote: mg::EndpointId(if role == mg::Role::Client { 2 } else { 1 }),
            lane: mg::LaneId(LANE),
        };
        let records = match input.material {
            establish::InitialMaterial::Legacy(root) => {
                if contract.refresh_selection().is_some() {
                    return Err(invalid("legacy material cannot install managed Records"));
                }
                record::Records::new(
                    root,
                    security::LaneId(LANE),
                    config.security,
                    security::Protection::ChaCha20Poly1305,
                    input.cover,
                    control_scope,
                    data_scope,
                )
            }
            establish::InitialMaterial::Managed(initial) => {
                if Some(initial.selection()) != contract.refresh_selection()
                    || initial.authenticated() != input.info.authenticated
                {
                    return Err(invalid(
                        "managed contract differs from actual initial authority",
                    ));
                }
                let elapsed = Instant::now()
                    .checked_duration_since(origin)
                    .ok_or_else(|| invalid("managed original clock is in the future"))?;
                let now = u64::try_from(elapsed.as_micros()).map_err(invalid)?;
                let expires = u64::try_from(config.lifetime.lease.as_micros()).map_err(invalid)?;
                record::Records::new_refreshable(
                    initial,
                    security::LaneId(LANE),
                    config.security,
                    security::Protection::ChaCha20Poly1305,
                    input.cover,
                    control_scope,
                    data_scope,
                    l2tunnel::handshake::Time(now),
                    l2tunnel::handshake::Time(expires),
                )
            }
        }
        .map_err(invalid)?;
        let capacity = records
            .capacity(config.security.max_body_bytes)
            .map_err(invalid)?;
        let binding = delivery::Binding {
            session: identity.session,
            lane: identity.lane,
            local_role: role,
            control_epoch: config.control_epoch.0,
        };
        let plans = provision::ControlPlan::new(&contract, binding)?;
        let wrapper_plan = plans.wrapper(config.control)?;
        let message_bytes = plans.capacity_bytes()?;
        let message_max = plans.maximum_message_bytes()?;
        let buffer_plan = buffers::Buffers::plan(
            input.cover.limits().max_packet_bytes,
            capacity
                .seal_workspace_bytes
                .max(capacity.open_workspace_bytes),
            config.security.max_body_bytes,
            plans.maximum_packet_bytes(config.control)?,
            message_max,
            config.security.max_body_bytes,
        )?;
        let input_plan = buffers::Inputs::plan(
            READ_BUFFER_BYTES,
            input
                .cover
                .limits()
                .max_packet_bytes
                .checked_add(1)
                .ok_or_else(exhausted)?,
        )?;
        let max_native = contract
            .initial()
            .descriptor()
            .local(role)
            .receive()
            .max_native();
        let native_plan = native_storage::Queue::<common_native::CommonNative>::plan(
            config.native.pending_packets,
            config.native.pending_bytes,
            max_native,
        )?;
        // Fixed witness scratch covers the unchanged Packed maximum, regardless
        // of which catalog entry is initially active. It is not a native fence.
        let witness_count = 255usize;
        let witness_bytes = witness_count
            .checked_mul(std::mem::size_of::<
                l2tunnel_codec::aligned_receiver::UnitWitness,
            >())
            .ok_or_else(exhausted)?;
        // The State stores only the fallible Bank cell header. The actual Bank
        // (including both inline Engine extents) is charged by its own Plan.
        let external = std::mem::size_of::<Driver>()
            .checked_add(std::mem::size_of::<owner::StateCell<Driver>>())
            .and_then(|v| v.checked_add(std::mem::size_of::<transactions::CommonState>()))
            .and_then(|v| v.checked_add(std::mem::size_of::<buffers::Inputs>()))
            .and_then(|v| v.checked_add(buffer_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(input_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(native_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(message_bytes))
            .and_then(|v| v.checked_add(input.io_capacity))
            .and_then(|v| v.checked_add(wrapper_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(witness_bytes))
            .and_then(|v| v.checked_add(input.cover.limits().max_packet_bytes))
            .ok_or_else(exhausted)?;
        let initial_plan = engine::storage::Plan::for_engine(
            contract.initial(),
            engine::Context {
                session: u128::from_be_bytes(identity.session.0),
                epoch: config.data_epoch.0,
                role,
            },
            contract.geometry(),
            contract.native_limits()?,
        )
        .map_err(invalid)?;
        let bank_plan = l2tunnel::record_bank::storage::Plan::for_bank(initial_plan, external)
            .map_err(invalid)?;
        if bank_plan.capacity_bytes() > contract.settings().retained_bytes {
            return Err(io::Error::other(
                l2tunnel::record_bank::storage::Error::Limit {
                    required: bank_plan.capacity_bytes(),
                    limit: contract.settings().retained_bytes,
                },
            ));
        }
        let control = plans.construct(config, binding, control_scope, data_scope, wrapper_plan)?;
        let buffers = buffers::Buffers::with_plan(buffer_plan)?;
        let inputs = buffers::Inputs::with_plan(input_plan)?;
        let input_capacity = inputs.capacity_bytes();
        let native = native_storage::Queue::with_plan(native_plan)?;
        let mut witnesses = Vec::new();
        witnesses
            .try_reserve_exact(witness_count)
            .map_err(io::Error::other)?;
        if witnesses.capacity() != witness_count {
            return Err(invalid("common witness capacity differs"));
        }
        witnesses.resize(
            witness_count,
            l2tunnel_codec::aligned_receiver::UnitWitness {
                identity: l2tunnel_codec::aligned_receiver::RecordIdentity {
                    channel: l2tunnel_codec::aligned_receiver::ChannelId(0),
                    record: l2tunnel_codec::aligned_receiver::RecordId(0),
                },
                index: 0,
                count: 1,
            },
        );
        let mut wire = Vec::new();
        wire.try_reserve_exact(input.cover.limits().max_packet_bytes)
            .map_err(io::Error::other)?;
        if wire.capacity() != input.cover.limits().max_packet_bytes {
            return Err(invalid("common sealed wire capacity differs"));
        }
        wire.resize(wire.capacity(), 0);
        let owner = reserve_common_state(
            &contract,
            identity,
            control.transaction_binding()?,
            external,
        )?;
        let reserve = contract.reserve()?;
        let current = contract.initial();
        let local_policy = current.descriptor().local(role);
        let send_rate = local_policy.send().common().bytes_per_second();
        let burst = local_policy.send().common().burst_bytes();
        let lease = add(0, config.lifetime.lease)?;
        origin
            .checked_add(config.lifetime.lease)
            .ok_or_else(|| invalid("generic lease exceeds runtime clock"))?;
        let next_report = config
            .report_interval
            .map(|interval| add(0, interval))
            .transpose()?;
        // Complete ownership here. The carrier moves this same Driver into its
        // existing cell without retaining additional inline Driver return slots
        // in callers while the reserved Bank is being constructed.
        finish(
            companion,
            Self {
                config,
                info: input.info,
                cover: input.cover,
                origin,
                bootstrap: input.bootstrap,
                joining: input.joining,
                outer: input.next_outer,
                records,
                owner: owner::DataOwner::Common(owner),
                generic: None,
                common: Some(Runtime {
                    contract,
                    action: None,
                    request: None,
                    cursor: false,
                    native_work: [0; 2],
                    sealed: None,
                    wire,
                    outcome: None,
                    completion: None,
                    observation_dirty: false,
                    witnesses,
                    sent: None,
                    delivered: None,
                    rolling_scheduler_steps: 0,
                    rolling_work_used: [0; 3],
                    path: SameFlowRecovery::default(),
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
                native: common_native::OutputQueue::Common(native),
                // Inactive compatibility storage: width zero cannot authorize a
                // Swift completion. Common uses its actual Engine tokens/counts.
                written: NativeWritten {
                    origin: NativeOrigin::new(&input.info, data_scope, records::Direction::Receive),
                    channels: 0,
                    counts: [0; swift::MAX_CHANNELS],
                },
                retired_send: None,
                retired_receive: None,
                bucket: Bucket::new(send_rate, burst),
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
        )
    }

    pub(super) fn snapshot_common(&self, now: u64, running: bool) -> io::Result<CommonSnapshot> {
        let state = self.common_state()?;
        let runtime = self
            .common
            .as_ref()
            .ok_or_else(|| protocol("common runtime missing"))?;
        let current = *state.current();
        let local = current
            .descriptor()
            .local(common_contract::mg_role(self.info.role));
        let mut counters = self.counters;
        counters.native_pending_packets = self.native.len();
        counters.native_pending_bytes = self.native.bytes();
        counters.native_storage_capacity_bytes = self.native.capacity_bytes();
        counters.workspace_capacity_bytes = self.buffers.capacity_bytes();
        Ok(CommonSnapshot {
            running,
            elapsed_micros: now,
            info: self.info,
            configuration: runtime.contract.expected_configuration(),
            physical_scope: self.source_scope,
            current,
            requested: runtime
                .request
                .as_ref()
                .map(|request| request.configuration),
            operation: state.peer().operation(),
            epoch: state.epoch(),
            phase: state.peer().phase(),
            storage: state.usage(),
            resource_preallocation_complete: false,
            engine: state.engine(state.epoch())?.statistics(),
            send_rate: local.send().common().bytes_per_second(),
            receive_rate: local.receive().common().bytes_per_second(),
            send_channels: local.send().channels(),
            receive_channels: local.receive().channels(),
            rolling_work: self.config.rolling_work,
            rolling_scheduler_steps: runtime.rolling_scheduler_steps,
            rolling_work_used: runtime.rolling_work_used,
            performance: self.performance.snapshot(now, &self.bucket),
            control: self.control.retained(),
            counters,
            liveness: self.live,
            path_recovery: runtime.path,
            terminal: self.terminal,
        })
    }
}

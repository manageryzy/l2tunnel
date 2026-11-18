//! Explicit generic construction and observation, sharing the sole runtime owner.

use super::common_actions::ActionWork;
use super::*;
use l2tunnel::record_configuration::Configuration as C;
use l2tunnel::{record_bank::storage, record_engine as engine};

#[path = "transport_compact_arq_trace.rs"]
pub(super) mod compact_arq_trace;
#[path = "transport_common_managed.rs"]
mod managed;
#[path = "transport_common_provision.rs"]
mod provision;
#[cfg(unix)]
#[path = "transport_common_proxy.rs"]
mod proxy_records;
#[path = "transport_wire_metrics.rs"]
pub(super) mod wire_metrics;
pub use managed::run_common_on_carrier;
#[cfg(unix)]
pub(crate) use proxy_records::{
    run_common_proxy_records, run_common_proxy_records_on_maintained,
    run_common_proxy_records_on_raw,
};
#[path = "transport_common_raw.rs"]
mod raw;
pub use raw::run_common_on_raw;
#[path = "transport_common_maintained.rs"]
mod maintained;
pub use maintained::run_common_on_maintained;

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

/// Actual Common transaction and retained-carrier observations.
#[derive(Clone, Debug)]
pub struct CommonSnapshot {
    /// Independent native delivery owners in actual current/draining epochs.
    pub native_delivery: [Option<NativeDeliverySnapshot>; 2],
    /// Actual maintained TLS/QUIC policy and original authenticated lanes.
    /// Its geometry is an admission allowance, not a measured wire-byte total.
    pub maintained: Option<crate::secure_udp::maintained::Authenticated>,
    /// Actual local send completion boundary used to start recovery timers.
    pub send_boundary: crate::secure_udp::SendBoundary,
    /// Actual installed final record format, populated by every Common owner.
    pub compact_wire: Option<record::compact::Selection>,
    /// Proxy records contain control and always require strong authentication.
    pub authenticated_proxy_records: bool,
    /// Actual final record data framing and protection bytes, excluding carrier cost.
    pub effective_data_overhead_bytes: usize,
    /// Actual single-protection geometry installed on the original raw owner.
    pub raw_final_geometry: Option<l2tunnel_raw_io::handoff::pairing::packet::RecordGeometry>,
    /// Last actual strong feedback PN, independent from the Data repair seed.
    pub compact_feedback_number: Option<security::PacketNumber>,
    /// Actual sticky per-domain check failures under the original selected cap.
    pub compact_check_status: Option<record::compact::CheckStatus>,
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
    /// Selected local admission byte rate; maintained carriers use an allowance.
    pub send_rate: u64,
    /// Selected remote admission byte rate; maintained carriers use an allowance.
    pub receive_rate: u64,
    /// Actual local sending width.
    pub send_channels: u16,
    /// Actual local receiving width.
    pub receive_channels: u16,
    /// Actual independent directional work cap, at most four schedulers per turn.
    pub rolling_work: Option<l2tunnel_fec::rolling::WorkBudget>,
    /// Exact configured local wire-input policy, inactive on non-Rolling generations.
    pub rolling_ingress: Option<l2tunnel::rolling_records::IngressLimits>,
    /// Actual current-generation input queue observation, absent when inactive.
    pub rolling_input: Option<l2tunnel::rolling_records::IngressStatus>,
    /// Effective local queue-aware budget in the active record generation.
    pub rolling_repair_budget: Option<l2tunnel::rolling_records::RepairBudgetStatus>,
    /// Actual current Engine fragment selection; absent for other record families.
    pub rolling_fragments: Option<engine::FragmentPolicy>,
    /// Actual independently retained reassembly and completed-body custody.
    pub fragment_ingress: Option<engine::FragmentIngressSnapshot>,
    /// Actual logical reservation and physical completion counters.
    pub fragment_statistics: Option<engine::FragmentStatistics>,
    /// Actual sending and receiving rolling scheduler steps since construction.
    pub rolling_scheduler_steps: u64,
    /// Actual cumulative GF, copy and metadata work, respectively.
    pub rolling_work_used: [u64; 3],
    /// New authenticated data fragments refused by actual full completion custody.
    pub fragment_data_drops: u64,
    /// New authenticated feedback fragments refused by the dedicated retained slot.
    pub fragment_feedback_drops: u64,
    /// Actual current Engine-owned optional ACK ingress, not a requested-as-effective projection.
    pub ack_ingress: Option<engine::IngressSnapshot>,
    /// Actual installed independent cohort and source-free local observations.
    pub connections: Option<engine::ConnectionSnapshot>,
    /// Actual separate deferred raw input owner, not a reliable delivery ledger.
    pub connection_input: Option<ConnectionIngressSnapshot>,
    /// Actual selected controller, distinct from finite qualification/capability.
    pub connection_reuse_selected: bool,
    /// Actual immutable operation/cap and current semantic progress.
    pub connection_reuse: Option<super::common_reuse::ConnectionReuseSnapshot>,
    /// Actual fixed selected reuse payload; included once in external capacity.
    pub connection_reuse_reserved_bytes: usize,
    /// Actual fixed reuse allocation count, separate from nested protocol totals.
    pub connection_reuse_allocations: usize,
    /// Actual held native read awaiting typed ingress admission.
    pub pending_ingress_bytes: Option<usize>,
    /// First actual read time, not a TCP creation timestamp.
    pub pending_ingress_since_micros: Option<u64>,
    /// Original retained read cap; replacement or retry never renews it.
    pub pending_ingress_deadline_micros: Option<u64>,
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

/// Actual native-byte window status, separate from recovery debt and TCP cwnd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDeliverySnapshot {
    /// Exact original negotiated data epoch.
    pub epoch: u64,
    /// Exact complete policy owning these counters.
    pub configuration: security::ConfigDigest,
    /// Local actual admission, full-carrier acceptance and peer-device delivery.
    pub send: Option<l2tunnel::flow_control::delivery_window::Status>,
    /// A completed local native write awaits reliable control admission.
    pub pending_receipt: bool,
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
pub struct CommonControlHandle(pub(super) mpsc::Sender<Command>);

/// Unique bounded complete-configuration request receiver.
pub struct CommonControlRequests(pub(super) mpsc::Receiver<Command>);
#[allow(clippy::large_enum_variant)] // The single bounded slot already owns the complete inline configuration.
pub(super) enum Command {
    Switch(C, TransactionReply),
    Reuse(super::common_reuse::Request, super::common_reuse::Reply),
}

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
            .try_send(Command::Switch(configuration, sender))
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
    pub(super) feedback: bool,
    pub(super) cost: usize,
    pub(super) deadline: u64,
    pub(super) carrier: Option<l2tunnel::record_bank::CarrierOutputToken>,
    pub(super) fragment: Option<l2tunnel::record_bank::FragmentOutputToken>,
    pub(super) proxy_record: Option<l2tunnel_codec::aligned_receiver::UnitWitness>,
}
/// One emitted algorithm body waiting for actual carrier metadata, in the same wire slab.
pub(super) struct PendingPlain {
    pub(super) scope: Scope,
    pub(super) number: security::PacketNumber,
    pub(super) bytes: usize,
    pub(super) feedback: bool,
    pub(super) cost: usize,
    pub(super) deadline: u64,
    pub(super) carrier: Option<l2tunnel::record_bank::CarrierOutputToken>,
    pub(super) fragment: Option<l2tunnel::record_bank::FragmentOutputToken>,
    pub(super) proxy_record: Option<l2tunnel_codec::aligned_receiver::UnitWitness>,
}
/// One management emission awaiting the same raw lane reservation.
pub(super) struct PendingRawControl {
    pub(super) bytes: usize,
    pub(super) wire_bytes: usize,
    pub(super) deadline: Instant,
}
// Created only after the sole Records opener commits this exact User record.
// Public copied metadata cannot install or reconstruct this retained authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingFeedback {
    pub(super) encoding: common_fragments::FeedbackEncoding,
    // Exact pending physical User number; Some only for causal Research input.
    pub(super) physical_dependency: Option<u64>,
    pub(super) physical_arrival: Option<Instant>,
    pub(super) scope: Scope,
    pub(super) number: u64,
    pub(super) bytes: usize,
    pub(super) received: u64,
    pub(super) deadline: u64,
}
/// Metadata for the one actual packet retained in the existing Inputs.native slab.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingIngress {
    pub(super) generation: l2tunnel::record_bank::GenerationId,
    pub(super) epoch: core::Epoch,
    pub(super) bytes: usize,
    pub(super) received: u64,
    pub(super) deadline: u64,
}
pub(super) struct Runtime {
    pub(super) buffer_metrics: Option<crate::buffer_metrics::Observer>,
    pub(super) next_raw_buffer_sample: u64,
    pub(super) wire_metrics: Option<wire_metrics::Observer>,
    pub(super) wire_sample: Option<wire_metrics::Sample>,
    pub(super) compact_arq_trace: Option<compact_arq_trace::Observer>,
    #[cfg(unix)]
    pub(super) proxy_bridge: Option<crate::proxy::common_bridge::Bridge>,
    pub(super) reuse_owner: Option<owner::StateCell<super::common_reuse::Installed>>,
    pub(super) contract: CommonTransactionContract,
    pub(super) action: Option<ActionWork>,
    pub(super) request: Option<PendingRequest>,
    pub(super) cursor: bool,
    pub(super) native_work: [usize; 2],
    pub(super) sealed: Option<PendingWire>,
    pub(super) unsealed: Option<PendingPlain>,
    pub(super) raw_control: Option<PendingRawControl>,
    pub(super) raw_control_turn: bool,
    pub(super) raw_final_geometry:
        Option<l2tunnel_raw_io::handoff::pairing::packet::RecordGeometry>,
    pub(super) wire: Vec<u8>,
    pub(super) pending_feedback: Option<PendingFeedback>,
    pub(super) compact_feedback_number: Option<security::PacketNumber>,
    pub(super) pending_ingress: Option<PendingIngress>,
    pub(super) feedback_input: Vec<u8>,
    pub(super) connection_input: Option<common_connections::Input>,
    pub(super) outcome: Option<transactions::Outcome>,
    pub(super) completion: Option<(TransactionReply, Result<core::Epoch, SwitchError>)>,
    pub(super) observation_dirty: bool,
    pub(super) witnesses: Vec<l2tunnel_codec::aligned_receiver::UnitWitness>,
    pub(super) sent: Option<super::common_actions::Boundary>,
    pub(super) delivered: Option<super::common_actions::Boundary>,
    pub(super) rolling_scheduler_steps: u64,
    pub(super) rolling_work_used: [u64; 3],
    pub(super) fragment_data_drops: u64,
    pub(super) fragment_feedback_drops: u64,
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
    D: NativeDevice + Send,
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

async fn run_prepared_common<D, R: super::raw_carrier::RawBacking>(
    prepared: io::Result<PreparedRuntime<D, R>>,
    requests: Option<CommonControlRequests>,
    shutdown: impl Future<Output = ()> + Send,
    mut observe: impl FnMut(&CommonSnapshot) + Send,
) -> io::Result<CommonStopped>
where
    D: NativeDevice + Send,
{
    let PreparedRuntime {
        device,
        socket,
        mut driver,
        setup_deadline,
    } = prepared?;
    let completion = run_driver_clock(
        device,
        socket,
        &mut driver,
        setup_deadline,
        Requests::Common(requests),
        shutdown,
        move |driver, now, running| {
            observe(&driver.snapshot_common(now, running)?);
            Ok(())
        },
        Instant::now,
    )
    .await?;
    if driver.common.is_none() {
        return Err(protocol("common loop returned another backend"));
    }
    Ok(CommonStopped {
        reason: completion.reason,
        snapshot: driver.snapshot_common(completion.at, false)?,
    })
}

struct PreparedRuntime<D, R: super::raw_carrier::RawBacking = super::raw_carrier::NoRaw> {
    device: D,
    socket: carrier::IoOwner<R>,
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
    D: NativeDevice + Send,
{
    contract.require_native_adapter()?;
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
    let (socket, driver) = Driver::new_common(parts, contract, origin, |socket, driver| {
        Ok((socket, owner::StateCell::new(driver)?))
    })?;
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
    timing: &mut crate::initialization_timing::Timing,
    rolling_wait_diagnostics: bool,
) -> io::Result<owner::ReservedCommonState> {
    let config = contract.resources();
    timing.enter_at(
        crate::initialization_timing::Stage::BankConstruction,
        Instant::now(),
    );
    let mut bank = common_engines::Bank::new_selected(
        identity,
        core::Epoch(config.data_epoch.0),
        contract.initial(),
        contract.geometry(),
        contract.native_limits()?,
        storage::Limits {
            capacity_bytes: contract.settings().retained_bytes,
        },
        external,
        config.ack_coalescing,
        config.rolling_ingress,
        config.rolling_fragments,
        Some(contract.feedback_overhead_bytes()?),
        rolling_wait_diagnostics,
    )?;
    timing.enter_at(
        crate::initialization_timing::Stage::BankActivation,
        Instant::now(),
    );
    bank.enable_compact_wire(contract.feedback_overhead_bytes()?)?;
    timing.enter_at(
        crate::initialization_timing::Stage::TransactionConstruction,
        Instant::now(),
    );
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

// Keep final Driver scratch off the stack while the Bank constructs its actual
// reserved Engines. This continuation starts only after reservation returns and
// assembles the charged Common cell and Driver without retaining another Driver
// owner, preserving the original construction order.
#[inline(never)]
fn assemble_common_driver<T>(assemble: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    assemble()
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
    // Place the completed Driver directly in its caller's retained owner. Returning
    // it inline through both constructors multiplies debug scratch-stack extent.
    pub(super) fn new_common<T>(
        parts: member::Parts,
        contract: CommonTransactionContract,
        origin: Instant,
        finish: impl FnOnce(tokio::net::UdpSocket, Self) -> io::Result<T>,
    ) -> io::Result<T> {
        if contract.extra_wire_bytes() != 0
            || contract.raw_outer().is_some()
            || contract.maintained_outer().is_some()
        {
            return Err(invalid(
                "original UDP Common requires the original UDP contract",
            ));
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
        Self::new_common_input(input, contract, origin, parts.socket, finish)
    }

    fn new_common_input<S, T>(
        input: CommonInput,
        contract: CommonTransactionContract,
        origin: Instant,
        companion: S,
        finish: impl FnOnce(S, Self) -> io::Result<T>,
    ) -> io::Result<T> {
        use crate::initialization_timing::{
            Outcome as TimingOutcome, Owner as TimingOwner, Stage as TimingStage, Timing,
        };
        let mut timing = Timing::from_environment(TimingOwner::CommonConstruction, Instant::now());
        timing.enter_at(TimingStage::ContractAndRecords, Instant::now());
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
        let ip = contract.physical_overhead_bytes()?;
        let control_scope = Scope {
            epoch: config.control_epoch,
            configuration: expected,
        };
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
        let establish::InitialMaterial::Legacy(root) = input.material else {
            return Err(invalid(
                "Common requires the initial-only authenticated root",
            ));
        };
        let records = record::Records::new_compact_with_layout(
            root,
            security::LaneId(LANE),
            config.security,
            input.cover,
            control_scope,
            data_scope,
            contract.compact_wire(),
            if contract.on_outer_carrier() || contract.raw_outer().is_some() {
                record::compact::Layout::Carrier
            } else {
                record::compact::Layout::Original
            },
        )
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
        timing.enter_at(TimingStage::ControlAndExternalPlanning, Instant::now());
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
        let connection_plan = config
            .connection_ingress
            .map(|limits| limits.plan(config.security.max_body_bytes))
            .transpose()?;
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
        let reuse_bytes = if contract.connection_reuse() {
            super::common_reuse::Installed::capacity_bytes()?
        } else {
            0
        };
        // Common state has its own cell. Validate and charge the complete
        // payload before provisioning.
        std::alloc::Layout::array::<Runtime>(1).map_err(io::Error::other)?;
        let external = std::mem::size_of::<Driver>()
            .checked_add(std::mem::size_of::<owner::StateCell<Driver>>())
            .and_then(|v| v.checked_add(std::mem::size_of::<Runtime>()))
            .and_then(|v| v.checked_add(std::mem::size_of::<transactions::CommonState>()))
            .and_then(|v| v.checked_add(std::mem::size_of::<buffers::Inputs>()))
            .and_then(|v| v.checked_add(buffer_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(input_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(native_plan.capacity_bytes()))
            .and_then(|v| {
                v.checked_add(
                    connection_plan
                        .as_ref()
                        .map_or(0, |plan| plan.capacity_bytes()),
                )
            })
            .and_then(|v| v.checked_add(reuse_bytes))
            .and_then(|v| v.checked_add(records.compact_owner_bytes()))
            .and_then(|v| v.checked_add(message_bytes))
            .and_then(|v| v.checked_add(input.io_capacity))
            .and_then(|v| v.checked_add(wrapper_plan.capacity_bytes()))
            .and_then(|v| v.checked_add(witness_bytes))
            .and_then(|v| v.checked_add(input.cover.limits().max_packet_bytes))
            // The Vec/metadata headers are already in the charged Runtime; this is
            // the one actual retained authenticated-feedback payload capacity.
            .and_then(|v| v.checked_add(config.security.max_body_bytes))
            .ok_or_else(exhausted)?;
        let context = engine::Context {
            session: u128::from_be_bytes(identity.session.0),
            epoch: config.data_epoch.0,
            role,
        };
        timing.enter_at(TimingStage::EngineAndBankPlanning, Instant::now());
        let rolling_wait_diagnostics = std::env::var_os("L2TUNNEL_BUFFER_METRICS")
            .or_else(|| std::env::var_os("L2TUNNEL_WIRE_METRICS"))
            .is_some();
        let initial_plan = engine::storage::Plan::for_engine_with_compact_wire_and_fragmentation(
            contract.initial(),
            context,
            contract.geometry(),
            contract.native_limits()?,
            config.ack_coalescing,
            config.rolling_ingress,
            common_contract::selected_fragment_policy(
                &contract.initial(),
                config.rolling_fragments,
            ),
            contract.feedback_overhead_bytes()?,
        )
        .map_err(invalid)?;
        let initial_plan = if rolling_wait_diagnostics {
            initial_plan
                .with_rolling_wait_diagnostics()
                .and_then(|plan| plan.with_reliable_output_diagnostics())
                .and_then(|plan| plan.with_receiver_handoff_diagnostics())
                .map_err(invalid)?
        } else {
            initial_plan
        };
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
        // Allocate only after the complete external subtotal passed its admission.
        // Explicit diagnostics have their own bounded, reported heap; they never
        // borrow protocol storage or enlarge the authenticated protocol quota.
        timing.enter_at(TimingStage::AuxiliaryConstruction, Instant::now());
        let wire_metrics =
            wire_metrics::Observer::from_environment(input.cover.limits().max_packet_bytes)?;
        let compact_arq_trace = compact_arq_trace::Observer::from_environment()?;
        let mut buffer_metrics =
            crate::buffer_metrics::Observer::from_environment_at("common", origin)?;
        if let Some(metrics) = &mut buffer_metrics {
            let maximum_owners = contract
                .catalog()
                .descriptors()
                .iter()
                .map(|descriptor| match descriptor.profile() {
                    l2tunnel::record_configuration::Profile::PerConnectionCompact {
                        forward,
                        reverse,
                    } => usize::from(forward.owners).max(usize::from(reverse.owners)),
                    l2tunnel::record_configuration::Profile::Swift { forward, reverse } => {
                        // Validated Swift has at most 64 channels; reserve the
                        // shared packing row once plus each actual channel.
                        forward.channels.max(reverse.channels) + 1
                    }
                    // Other shared codec channels do not create independent owners.
                    _ => 1,
                })
                .max()
                .unwrap_or(1);
            metrics.configure_protocol_buffers(maximum_owners, role)?;
            let maximum_flows = contract
                .catalog()
                .descriptors()
                .iter()
                .map(|descriptor| {
                    descriptor
                        .local(role)
                        .send()
                        .common()
                        .pipeline()
                        .flows
                        .capacity
                })
                .max()
                .unwrap_or(1);
            metrics.configure_pipeline_admission(maximum_flows)?;
            if contract.catalog().descriptors().iter().any(|descriptor| {
                matches!(
                    descriptor.profile(),
                    l2tunnel::record_configuration::Profile::Rolling { .. }
                        | l2tunnel::record_configuration::Profile::RollingCopies { .. }
                        | l2tunnel::record_configuration::Profile::Research { .. }
                )
            }) {
                metrics
                    .protocol_buffers()
                    .ok_or_else(|| invalid("rolling buffer observer"))?
                    .configure_rolling_waits()?;
            }
            if contract.catalog().descriptors().iter().any(|descriptor| {
                matches!(
                    descriptor.profile(),
                    l2tunnel::record_configuration::Profile::Aligned { .. }
                        | l2tunnel::record_configuration::Profile::Packed { .. }
                )
            }) {
                metrics
                    .protocol_buffers()
                    .ok_or_else(|| invalid("reliable buffer observer"))?
                    .configure_reliable_output()?;
            }
            if contract.catalog().descriptors().iter().any(|descriptor| {
                matches!(
                    descriptor.profile(),
                    l2tunnel::record_configuration::Profile::Aligned { .. }
                        | l2tunnel::record_configuration::Profile::Packed { .. }
                        | l2tunnel::record_configuration::Profile::AlignedCompact { .. }
                        | l2tunnel::record_configuration::Profile::PackedCompact { .. }
                )
            }) {
                metrics
                    .protocol_buffers()
                    .ok_or_else(|| invalid("receiver handoff observer"))?
                    .configure_receiver_handoff()?;
            }
            metrics.configure_management_buffers()?;
        }
        let reuse_owner = if contract.connection_reuse() {
            Some(owner::StateCell::new(super::common_reuse::Installed::new())?)
        } else {
            None
        };
        let mut control =
            plans.construct(config, binding, control_scope, data_scope, wrapper_plan)?;
        if buffer_metrics.is_some() {
            control.enable_buffer_metrics();
        }
        let buffers = buffers::Buffers::with_plan(buffer_plan)?;
        let inputs = buffers::Inputs::with_plan(input_plan)?;
        let input_capacity = inputs.capacity_bytes();
        let native = native_storage::Queue::with_plan(native_plan)?;
        let connection_input = config
            .connection_ingress
            .zip(connection_plan)
            .map(|(limits, plan)| common_connections::Input::new(limits, plan))
            .transpose()?;
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
        let mut feedback_input = Vec::new();
        feedback_input
            .try_reserve_exact(config.security.max_body_bytes)
            .map_err(io::Error::other)?;
        if feedback_input.capacity() != config.security.max_body_bytes {
            return Err(invalid("common retained feedback capacity differs"));
        }
        feedback_input.resize(config.security.max_body_bytes, 0);
        let owner = reserve_common_state(
            &contract,
            identity,
            control.transaction_binding()?,
            external,
            &mut timing,
            rolling_wait_diagnostics,
        )?;
        timing.enter_at(TimingStage::DriverAssembly, Instant::now());
        let result = assemble_common_driver(move || {
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
            let common = owner::StateCell::new(Runtime {
                wire_metrics,
                buffer_metrics,
                next_raw_buffer_sample: 0,
                wire_sample: None,
                compact_arq_trace,
                #[cfg(unix)]
                proxy_bridge: None,
                reuse_owner,
                contract,
                action: None,
                request: None,
                cursor: false,
                native_work: [0; 2],
                sealed: None,
                unsealed: None,
                raw_control: None,
                raw_control_turn: false,
                raw_final_geometry: None,
                wire,
                pending_feedback: None,
                compact_feedback_number: None,
                pending_ingress: None,
                feedback_input,
                connection_input,
                outcome: None,
                completion: None,
                observation_dirty: false,
                witnesses,
                sent: None,
                delivered: None,
                rolling_scheduler_steps: 0,
                rolling_work_used: [0; 3],
                fragment_data_drops: 0,
                fragment_feedback_drops: 0,
                path: SameFlowRecovery::default(),
            })?;
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
                    common: Some(common),
                    source_scope: data_scope,
                    feedback_scope: data_scope,
                    target: None,
                    transaction_origin: None,
                    control,
                    control_work: false,
                    buffers,
                    inputs: Some(inputs),
                    envelope_rx: 1,
                    native: common_native::OutputQueue::Common(native),
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
        });
        timing.end_at(
            Instant::now(),
            if result.is_ok() {
                TimingOutcome::Complete
            } else {
                TimingOutcome::Failed
            },
        );
        result
    }

    pub(super) fn snapshot_common(&self, now: u64, running: bool) -> io::Result<CommonSnapshot> {
        let state = self.common_state()?;
        let runtime = self
            .common
            .as_deref()
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
        let mut native_delivery = [None; 2];
        for (index, epoch) in self.common_epochs().into_iter().flatten().enumerate() {
            let engine = state.engine(epoch)?;
            let send = engine
                .native_window_status(engine::Tick(now))
                .map_err(protocol)?;
            let pending_receipt = engine.pending_native_delivery().is_some();
            let local = engine
                .configuration()
                .descriptor()
                .local(common_contract::mg_role(self.info.role));
            if send.is_some()
                || matches!(
                    local.receive().common().native_window(),
                    l2tunnel::record_configuration::NativeWindow::Delivery(_)
                )
            {
                native_delivery[index] = Some(NativeDeliverySnapshot {
                    epoch: epoch.0,
                    configuration: common_actions::common_scope(epoch, engine.configuration())?
                        .configuration,
                    send,
                    pending_receipt,
                });
            }
        }
        Ok(CommonSnapshot {
            native_delivery,
            maintained: runtime.contract.maintained_outer(),
            send_boundary: runtime
                .contract
                .maintained_outer()
                .map_or(crate::secure_udp::SendBoundary::SocketAccepted, |outer| {
                    outer.requested().kind.send_boundary()
                }),
            compact_wire: Some(runtime.contract.compact_wire()),
            authenticated_proxy_records: runtime.contract.proxy_binding().is_some(),
            effective_data_overhead_bytes: {
                let selection = runtime.contract.compact_wire();
                if runtime.contract.proxy_binding().is_some() {
                    selection
                        .data_overhead()
                        .max(record::compact::AUTHENTICATED_OVERHEAD)
                } else {
                    selection.data_overhead()
                }
            },
            compact_check_status: Some(self.records.compact_check_status()),
            compact_feedback_number: runtime.compact_feedback_number,
            raw_final_geometry: runtime.raw_final_geometry,
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
            rolling_ingress: self.config.rolling_ingress,
            rolling_input: state.engine(state.epoch())?.rolling_ingress_status(),
            rolling_repair_budget: state.engine(state.epoch())?.rolling_repair_budget(),
            rolling_fragments: state.engine(state.epoch())?.fragment_policy(),
            fragment_ingress: state.engine(state.epoch())?.fragment_ingress_snapshot(),
            fragment_statistics: state.engine(state.epoch())?.fragment_statistics(),
            rolling_scheduler_steps: runtime.rolling_scheduler_steps,
            rolling_work_used: runtime.rolling_work_used,
            fragment_data_drops: runtime.fragment_data_drops,
            fragment_feedback_drops: runtime.fragment_feedback_drops,
            ack_ingress: state.engine(state.epoch())?.ingress_snapshot(),
            connections: state
                .engine(state.epoch())?
                .connection_snapshot()
                .map(|mut actual| {
                    actual.flow_reuse = runtime.contract.connection_reuse();
                    actual
                }),
            connection_reuse_selected: runtime.contract.connection_reuse(),
            connection_reuse: runtime.reuse_controller().map(|state| state.snapshot()),
            connection_reuse_reserved_bytes: runtime
                .reuse_owner
                .as_ref()
                .map_or(Ok(0), |_| super::common_reuse::Installed::capacity_bytes())?,
            connection_reuse_allocations: usize::from(runtime.reuse_owner.is_some()),
            connection_input: runtime
                .connection_input
                .as_ref()
                .map(common_connections::Input::snapshot),
            pending_ingress_bytes: runtime.pending_ingress.map(|pending| pending.bytes),
            pending_ingress_since_micros: runtime.pending_ingress.map(|pending| pending.received),
            pending_ingress_deadline_micros: runtime
                .pending_ingress
                .map(|pending| pending.deadline),
            performance: self.performance.snapshot(now, &self.bucket),
            control: self.control.retained(),
            counters,
            liveness: self.live,
            path_recovery: runtime.path,
            terminal: self.terminal,
        })
    }
}

impl Runtime {
    pub(super) fn reuse_controller(&self) -> Option<&super::common_reuse::Controller> {
        self.reuse_owner
            .as_ref()
            .and_then(|owner| owner.controller())
    }
}

//! Exact heap-only backing of the existing actual rolling-record composition.
use super::*;

/// Original complete nested heap allowance, excluding the inline Endpoint header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum actual retained nested heap capacity in bytes.
    pub capacity_bytes: usize,
}

/// Actual retained allocation layouts, not allocator bookkeeping, RSS or an OOM proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original immutable complete allowance.
    pub limit_bytes: usize,
    /// Actual nested codec, scheduler and scratch heap capacities.
    pub capacity_bytes: usize,
    /// Actual retained nonempty allocations across these owners.
    pub allocations: usize,
}

/// Complete allocation-free preflight of exactly the owners constructed below.
#[derive(Clone, Copy)]
pub struct Plan<P: RecoveryPolicy = scheduler::Policy> {
    config: Config<P>,
    copies: CopyPolicies,
    context: Context,
    stream: u32,
    now: Tick,
    pub(super) sender: recovery::OwnerPlan,
    pub(super) incoming: recovery::OwnerPlan,
    packing: codec::aligned_storage::PackedSenderPlan,
    receiver: codec::aligned_storage::ReceiverPlan,
    source_bytes: usize,
    symbol_bytes: usize,
    ingress: Option<IngressLimits>,
    framing: Option<OutputFraming>,
    ingress_bytes: usize,
    capacity_bytes: usize,
    wait_diagnostics: bool,
}
impl<P: RecoveryPolicy> Plan<P> {
    /// Validate both complete directions, every original time addition and layout.
    pub fn for_endpoint(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
    ) -> Result<Self, Error> {
        Self::for_endpoint_with_copies(config, context, stream, now, CopyPolicies::ONE)
    }
    /// Plan the same actual heap owners with exact selected directional policies.
    pub fn for_endpoint_with_copies(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
        copies: CopyPolicies,
    ) -> Result<Self, Error> {
        Self::for_endpoint_with_options(config, context, stream, now, copies, None)
    }
    /// Plan the same actual owners plus optional independently bounded input custody.
    pub fn for_endpoint_with_options(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
        copies: CopyPolicies,
        ingress: Option<IngressLimits>,
    ) -> Result<Self, Error> {
        Self::for_endpoint_with_output_framing(config, context, stream, now, copies, ingress, None)
    }
    /// Plan exact optional physical fragmentation without adding a payload owner.
    pub fn for_endpoint_with_output_framing(
        config: Config<P>,
        context: Context,
        stream: u32,
        now: Tick,
        copies: CopyPolicies,
        ingress: Option<IngressLimits>,
        framing: Option<OutputFraming>,
    ) -> Result<Self, Error> {
        copies.validate(config)?;
        if let Some(framing) = framing {
            framing.binding_digest(config, copies, stream)?;
        } else {
            copies.binding_digest(config, stream)?;
        }
        if context.session == 0 || context.epoch == 0 {
            return Err(Error::Configuration);
        }
        for direction in [config.forward, config.reverse] {
            let s = direction.scheduler;
            let recovery = s.recovery();
            let intervals = s.intervals();
            for interval in [
                direction.packing.packing.hold_micros,
                direction.receiver.lifetime_ticks,
                direction.codec_stage_micros,
                recovery.job_ticks,
                recovery.debt_ticks,
                recovery.handoff_ticks,
                intervals[0],
                intervals[1],
                config.native_stall_micros,
            ] {
                now.0.checked_add(interval).ok_or(Error::Arithmetic)?;
            }
        }
        let (send, receive, _) = config.local(context.role);
        let sender = send
            .scheduler
            .sender_plan()
            .map_err(Error::RollingStorage)?;
        let incoming = receive
            .scheduler
            .receiver_plan()
            .map_err(Error::RollingStorage)?;
        let packing = send.packing_plan()?;
        let receiver = receive.receiver_plan()?;
        let source_bytes = send
            .packing
            .envelope()
            .max_source_bytes()
            .map_err(Error::Envelope)?;
        let symbol_bytes = receive
            .receiver
            .body
            .symbol_bytes
            .checked_mul(usize::from(receive.packing.max_units))
            .ok_or(Error::Arithmetic)?;
        for count in [source_bytes, symbol_bytes] {
            std::alloc::Layout::array::<u8>(count).map_err(|_| Error::Arithmetic)?;
        }
        let ingress_bytes = ingress
            .map(|limits| limits.required_capacity(receive.maximum_packet_bytes()?))
            .transpose()?
            .unwrap_or(0);
        let capacity_bytes = [
            sender.capacity_bytes,
            incoming.capacity_bytes,
            packing.capacity_bytes(),
            receiver.capacity_bytes(),
            source_bytes,
            symbol_bytes,
            ingress_bytes,
            fin_order::Guard::planned_bytes(receive),
            previewed::Previewed::planned_bytes(receive),
            if send.scheduler.targeted() {
                repair_budget::Budget::heap_bytes(send.scheduler.recovery().window)
            } else {
                0
            },
        ]
        .into_iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value).ok_or(Error::Arithmetic)
        })?;
        Ok(Self {
            config,
            copies,
            context,
            stream,
            now,
            sender,
            incoming,
            packing,
            receiver,
            source_bytes,
            symbol_bytes,
            ingress,
            framing,
            ingress_bytes,
            capacity_bytes,
            wait_diagnostics: false,
        })
    }
    /// Select one bounded diagnostic sidecar before any owner allocation.
    /// Existing limits still apply; selection never increases an allowance.
    pub fn with_wait_diagnostics(mut self) -> Result<Self, Error> {
        if !self.wait_diagnostics {
            let bytes = std::mem::size_of::<waits::Snapshot>();
            std::alloc::Layout::array::<waits::Snapshot>(1).map_err(|_| Error::Arithmetic)?;
            self.capacity_bytes = self
                .capacity_bytes
                .checked_add(bytes)
                .ok_or(Error::Arithmetic)?;
            self.wait_diagnostics = true;
        }
        Ok(self)
    }
    /// Both complete globally ordered policies, unchanged.
    pub const fn config(&self) -> Config<P> {
        self.config
    }
    /// Exact complete global policies retained for actual construction.
    pub const fn source_copy_policies(&self) -> CopyPolicies {
        self.copies
    }
    /// Exact context used by the actual selected owner.
    pub const fn context(&self) -> Context {
        self.context
    }
    /// Exact authenticated coding stream.
    pub const fn stream(&self) -> u32 {
        self.stream
    }
    /// Exact constructor-time origin, supplied by the caller.
    pub const fn now(&self) -> Tick {
        self.now
    }
    /// Exact optional authenticated receive input custody.
    pub const fn ingress_limits(&self) -> Option<IngressLimits> {
        self.ingress
    }
    /// Exact complete global output framing, with no hidden reduction or default.
    pub const fn output_framing(&self) -> Option<OutputFraming> {
        self.framing
    }
    /// Complete heap-only capacity; an embedding owner counts Endpoint inline once.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}
impl<P: RecoveryPolicy> Endpoint<P> {
    /// Construct the same actual owners only after complete heap admission.
    pub fn new_reserved(plan: Plan<P>, limits: Limits) -> Result<Self, Error> {
        if plan.copies != CopyPolicies::ONE {
            return Err(Error::Configuration);
        }
        Self::new_reserved_with_copies(plan, limits)
    }
    /// Construct selected copy policies from their exact admitted complete plan.
    pub fn new_reserved_with_copies(plan: Plan<P>, limits: Limits) -> Result<Self, Error> {
        if plan.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity {
                required: plan.capacity_bytes,
                limit: limits.capacity_bytes,
            });
        }
        let mut endpoint = Self::construct(
            plan.config,
            plan.context,
            plan.stream,
            plan.now,
            Some(plan),
            endpoint::ConstructionOptions {
                copies: plan.copies,
                ingress: plan.ingress,
                framing: plan.framing,
            },
        )?;
        if plan.wait_diagnostics {
            endpoint
                .waits
                .try_reserve_exact(1)
                .map_err(|_| Error::Allocation)?;
            if endpoint.waits.capacity() != 1 {
                return Err(Error::StorageInvariant);
            }
            endpoint.waits.push(waits::Snapshot::new(
                endpoint.instance,
                endpoint.send_rolling_scope,
                plan.now,
            ));
            if endpoint.ingress.is_some()
                && let Some(snapshot) = endpoint.waits.first_mut()
            {
                snapshot.ingress_admission = Some(waits::ingress::Snapshot::default());
            }
        }
        let packing = endpoint
            .packing
            .storage_usage()
            .ok_or(Error::StorageInvariant)?;
        let receiver = endpoint
            .records
            .storage_usage()
            .ok_or(Error::StorageInvariant)?;
        let sender = P::sender_usage(&endpoint.sender).map_err(Error::RollingStorage)?;
        let incoming = P::receiver_usage(&endpoint.incoming).map_err(Error::RollingStorage)?;
        if packing.capacity_bytes != plan.packing.capacity_bytes()
            || receiver.capacity_bytes != plan.receiver.capacity_bytes()
            || sender.capacity_bytes != plan.sender.capacity_bytes
            || incoming.capacity_bytes != plan.incoming.capacity_bytes
            || sender.allocations != plan.sender.allocations
            || incoming.allocations != plan.incoming.allocations
            || endpoint.source.capacity() != plan.source_bytes
            || endpoint.symbols.capacity() != plan.symbol_bytes
            || endpoint
                .ingress
                .as_ref()
                .map_or(0, |owner| owner.usage().capacity_bytes)
                != plan.ingress_bytes
        {
            return Err(Error::StorageInvariant);
        }
        let capacity_bytes = [
            packing.capacity_bytes,
            receiver.capacity_bytes,
            sender.capacity_bytes,
            incoming.capacity_bytes,
            endpoint.source.capacity(),
            endpoint.symbols.capacity(),
            endpoint.fin_order.capacity_bytes(),
            endpoint.previewed.capacity_bytes(),
            endpoint
                .repair_budget
                .as_ref()
                .map_or(0, repair_budget::Budget::capacity_bytes),
            endpoint.waits.capacity() * std::mem::size_of::<waits::Snapshot>(),
            endpoint
                .ingress
                .as_ref()
                .map_or(0, |owner| owner.usage().capacity_bytes),
        ]
        .into_iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value).ok_or(Error::Arithmetic)
        })?;
        let allocations = [
            packing.allocations,
            receiver.allocations,
            sender.allocations,
            incoming.allocations,
            usize::from(endpoint.source.capacity() != 0),
            usize::from(endpoint.symbols.capacity() != 0),
            usize::from(endpoint.fin_order.capacity_bytes() != 0),
            usize::from(endpoint.previewed.capacity_bytes() != 0),
            usize::from(endpoint.repair_budget.is_some()),
            usize::from(endpoint.waits.capacity() != 0),
            endpoint
                .ingress
                .as_ref()
                .map_or(0, |owner| owner.usage().allocations),
        ]
        .into_iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value).ok_or(Error::Arithmetic)
        })?;
        if capacity_bytes != plan.capacity_bytes || capacity_bytes > limits.capacity_bytes {
            return Err(Error::StorageInvariant);
        }
        endpoint.usage = Some(Usage {
            limit_bytes: limits.capacity_bytes,
            capacity_bytes,
            allocations,
        });
        Ok(endpoint)
    }
    /// Complete observed backing, absent for explicit functional construction.
    pub const fn storage_usage(&self) -> Option<Usage> {
        self.usage
    }
}

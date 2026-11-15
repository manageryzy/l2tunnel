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
pub struct Plan {
    config: Config,
    context: Context,
    stream: u32,
    now: Tick,
    pub(super) sender: rolling::storage::Plan,
    pub(super) incoming: rolling::storage::Plan,
    packing: codec::aligned_storage::PackedSenderPlan,
    receiver: codec::aligned_storage::ReceiverPlan,
    source_bytes: usize,
    symbol_bytes: usize,
    capacity_bytes: usize,
}
impl Plan {
    /// Validate both complete directions, every original time addition and layout.
    pub fn for_endpoint(
        config: Config,
        context: Context,
        stream: u32,
        now: Tick,
    ) -> Result<Self, Error> {
        config.validate()?;
        config.binding_digest(stream)?;
        if context.session == 0 || context.epoch == 0 {
            return Err(Error::Configuration);
        }
        for direction in [config.forward, config.reverse] {
            let s = direction.scheduler;
            for interval in [
                direction.packing.packing.hold_micros,
                direction.receiver.lifetime_ticks,
                direction.codec_stage_micros,
                s.recovery.job_ticks,
                s.recovery.debt_ticks,
                s.recovery.handoff_ticks,
                s.tail_ticks,
                s.feedback_ticks,
                config.native_stall_micros,
            ] {
                now.0.checked_add(interval).ok_or(Error::Arithmetic)?;
            }
        }
        let (send, receive, _) = config.local(context.role);
        let sender =
            rolling::storage::Plan::for_sender(send.scheduler).map_err(Error::RollingStorage)?;
        let incoming = rolling::storage::Plan::for_receiver(receive.scheduler)
            .map_err(Error::RollingStorage)?;
        let packing = codec::aligned_storage::PackedSenderPlan::for_config(send.packing)
            .map_err(Error::Storage)?;
        let receiver = codec::aligned_storage::ReceiverPlan::for_limits(receive.receiver)
            .map_err(Error::Storage)?;
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
        let capacity_bytes = [
            sender.capacity_bytes(),
            incoming.capacity_bytes(),
            packing.capacity_bytes(),
            receiver.capacity_bytes(),
            source_bytes,
            symbol_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, value| {
            sum.checked_add(value).ok_or(Error::Arithmetic)
        })?;
        Ok(Self {
            config,
            context,
            stream,
            now,
            sender,
            incoming,
            packing,
            receiver,
            source_bytes,
            symbol_bytes,
            capacity_bytes,
        })
    }
    /// Both complete globally ordered policies, unchanged.
    pub const fn config(&self) -> Config {
        self.config
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
    /// Complete heap-only capacity; an embedding owner counts Endpoint inline once.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}
impl Endpoint {
    /// Construct the same actual owners only after complete heap admission.
    pub fn new_reserved(plan: Plan, limits: Limits) -> Result<Self, Error> {
        if plan.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Capacity {
                required: plan.capacity_bytes,
                limit: limits.capacity_bytes,
            });
        }
        let mut endpoint =
            Self::construct(plan.config, plan.context, plan.stream, plan.now, Some(plan))?;
        let packing = endpoint
            .packing
            .storage_usage()
            .ok_or(Error::StorageInvariant)?;
        let receiver = endpoint
            .records
            .storage_usage()
            .ok_or(Error::StorageInvariant)?;
        let sender = endpoint
            .sender
            .storage_usage()
            .map_err(Error::RollingStorage)?;
        let incoming = endpoint
            .incoming
            .storage_usage()
            .map_err(Error::RollingStorage)?;
        if packing.capacity_bytes != plan.packing.capacity_bytes()
            || receiver.capacity_bytes != plan.receiver.capacity_bytes()
            || sender.capacity_bytes != plan.sender.capacity_bytes()
            || incoming.capacity_bytes != plan.incoming.capacity_bytes()
            || sender.allocations != plan.sender.allocations()
            || incoming.allocations != plan.incoming.allocations()
            || endpoint.source.capacity() != plan.source_bytes
            || endpoint.symbols.capacity() != plan.symbol_bytes
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

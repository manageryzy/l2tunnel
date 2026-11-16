//! Actual bounded fixed-cohort backing; external Pipeline/security/I/O is excluded.
use super::*;
use std::{alloc::Layout, mem::size_of};

/// Complete fixed plus managed-heap allowance for this collection only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// No nested reservation may make the complete retained layout exceed this.
    pub capacity_bytes: usize,
}

/// Actual retained layouts, without allocator bookkeeping or external owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original caller allowance.
    pub limit_bytes: usize,
    /// Collection inline header counted exactly once.
    pub fixed_bytes: usize,
    /// Actual Slot vector plus every nested endpoint managed heap.
    pub heap_bytes: usize,
    /// Checked fixed plus heap total.
    pub capacity_bytes: usize,
    /// Actual nonzero reservations, including the owner vector.
    pub allocations: usize,
    /// Actual constructed independently stateful endpoint count.
    pub owners: u16,
}

/// Pure complete layout; it allocates and constructs no recovery owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: Config,
    endpoint: aligned::compact_storage::Plan,
    slot_bytes: usize,
    raw_send_bytes: usize,
    raw_receive_bytes: usize,
    heap_bytes: usize,
    capacity_bytes: usize,
}
impl Plan {
    /// Validate exact explicit policy, bounded route geometry and nested layouts.
    pub fn for_collection(config: Config) -> Result<Self, Error> {
        if !(1..=256).contains(&config.owners)
            || config.incarnation == 0
            || config.send.receiver.channels != 1
            || config.receive.receiver.channels != 1
            || config.send.copies.copies != 1
            || config.receive.copies.copies != 1
            || config
                .send_carrier_overhead_bytes
                .checked_add(route::HEADER_BYTES)
                != Some(config.send.recovery.outer_overhead_bytes())
            || config
                .receive_carrier_overhead_bytes
                .checked_add(route::HEADER_BYTES)
                != Some(config.receive.recovery.outer_overhead_bytes())
        {
            return Err(Error::Configuration);
        }
        if config.send_unreliable.is_some() != config.receive_unreliable.is_some() {
            return Err(Error::Configuration);
        }
        for (policy, native, carrier) in [
            (
                config.send_unreliable,
                config.send.receiver.body.max_frame_bytes,
                config.send_carrier_overhead_bytes,
            ),
            (
                config.receive_unreliable,
                config.receive.receiver.body.max_frame_bytes,
                config.receive_carrier_overhead_bytes,
            ),
        ] {
            if let Some(policy) = policy {
                policy.validate(native)?;
                let routed = policy
                    .max_bytes
                    .checked_add(route::HEADER_BYTES)
                    .ok_or(Error::Arithmetic)?;
                if routed > route::MAX_PACKET_BYTES
                    || routed.checked_add(carrier).ok_or(Error::Arithmetic)? > 65_535
                {
                    return Err(Error::Configuration);
                }
            }
        }
        let endpoint = aligned::compact_storage::Plan::for_duplex(config.send, config.receive)
            .map_err(Error::Storage)?;
        let reliable = endpoint.reliable_plan();
        for maximum in [
            reliable.send_max_packet_bytes(),
            reliable.receive_max_packet_bytes(),
        ] {
            if maximum
                .checked_add(route::HEADER_BYTES)
                .ok_or(Error::Arithmetic)?
                > route::MAX_PACKET_BYTES
            {
                return Err(Error::Configuration);
            }
        }
        let owners = usize::from(config.owners);
        let slot_bytes = Layout::array::<Slot>(owners)
            .map_err(|_| Error::Arithmetic)?
            .size();
        let nested = endpoint
            .capacity_bytes()
            .checked_mul(owners)
            .ok_or(Error::Arithmetic)?;
        let raw_send_bytes = config.send_unreliable.map_or(Ok(0), |p| {
            p.max_bytes.checked_mul(owners).ok_or(Error::Arithmetic)
        })?;
        let raw_receive_bytes = config.receive_unreliable.map_or(Ok(0), |p| {
            p.max_bytes.checked_mul(owners).ok_or(Error::Arithmetic)
        })?;
        Layout::array::<u8>(raw_send_bytes).map_err(|_| Error::Arithmetic)?;
        Layout::array::<u8>(raw_receive_bytes).map_err(|_| Error::Arithmetic)?;
        let heap_bytes = slot_bytes
            .checked_add(nested)
            .and_then(|n| n.checked_add(raw_send_bytes))
            .and_then(|n| n.checked_add(raw_receive_bytes))
            .ok_or(Error::Arithmetic)?;
        let capacity_bytes = size_of::<Collection>()
            .checked_add(heap_bytes)
            .ok_or(Error::Arithmetic)?;
        Ok(Self {
            config,
            endpoint,
            slot_bytes,
            raw_send_bytes,
            raw_receive_bytes,
            heap_bytes,
            capacity_bytes,
        })
    }

    /// Exact immutable requested fixed-cohort policy.
    pub const fn config(&self) -> Config {
        self.config
    }
    /// Actual managed Slot vector and nested endpoint heap layouts.
    pub const fn heap_bytes(&self) -> usize {
        self.heap_bytes
    }
    /// Complete collection inline plus managed heap layout.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
    /// Exact maximum routed outgoing bytes, excluding further security/cover bytes.
    pub fn send_max_packet_bytes(&self) -> usize {
        self.endpoint
            .reliable_plan()
            .send_max_packet_bytes()
            .max(self.config.send_unreliable.map_or(0, |p| p.max_bytes))
            + route::HEADER_BYTES
    }
    /// Exact maximum routed incoming bytes under the crossed actual geometry.
    pub fn receive_max_packet_bytes(&self) -> usize {
        self.endpoint
            .reliable_plan()
            .receive_max_packet_bytes()
            .max(self.config.receive_unreliable.map_or(0, |p| p.max_bytes))
            + route::HEADER_BYTES
    }
}

impl Collection {
    /// Construct only actual reserved owners; every failure drops earlier owners.
    pub fn new_reserved(
        plan: Plan,
        context: RecoveryContext,
        limits: Limits,
    ) -> Result<Self, Error> {
        if plan.capacity_bytes > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.capacity_bytes,
                limit: limits.capacity_bytes,
            });
        }
        let count = usize::from(plan.config.owners);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        let actual_slots = Layout::array::<Slot>(slots.capacity())
            .map_err(|_| Error::Arithmetic)?
            .size();
        if actual_slots != plan.slot_bytes {
            return Err(Error::Invariant);
        }
        let mut nested = 0usize;
        let mut allocations = 1usize;
        for _ in 0..count {
            let endpoint = aligned::Endpoint::new_compact_duplex_reserved(
                plan.config.send,
                plan.config.receive,
                context,
                aligned::storage::Limits {
                    capacity_bytes: plan.endpoint.capacity_bytes(),
                },
            )
            .map_err(Error::Storage)?;
            let usage = endpoint.storage_usage().ok_or(Error::Invariant)?;
            if usage.capacity_bytes != plan.endpoint.capacity_bytes() {
                return Err(Error::Invariant);
            }
            nested = nested
                .checked_add(usage.capacity_bytes)
                .ok_or(Error::Arithmetic)?;
            allocations = allocations
                .checked_add(usage.allocations)
                .ok_or(Error::Arithmetic)?;
            slots.push(Slot {
                endpoint,
                incarnation: plan.config.incarnation,
                admitted_native: 0,
                written_native: 0,
                retirement: None,
                retirement_serial: 0,
                highest_retirement_attempt: 0,
                native: None,
                next_native: 0,
                native_failure: None,
                claim: None,
                raw_send: None,
                raw_receive: None,
                next_raw_send: 0,
                next_raw_receive: 0,
                last_raw: None,
                raw_failure: None,
            });
        }
        let mut raw_send = Vec::new();
        let mut raw_receive = Vec::new();
        for (buffer, required) in [
            (&mut raw_send, plan.raw_send_bytes),
            (&mut raw_receive, plan.raw_receive_bytes),
        ] {
            if required > 0 {
                buffer
                    .try_reserve_exact(required)
                    .map_err(|_| Error::Allocation)?;
                if buffer.capacity() != required {
                    return Err(Error::Invariant);
                }
                buffer.resize(required, 0);
                allocations = allocations.checked_add(1).ok_or(Error::Arithmetic)?;
            }
        }
        let heap_bytes = actual_slots
            .checked_add(nested)
            .and_then(|n| n.checked_add(raw_send.capacity()))
            .and_then(|n| n.checked_add(raw_receive.capacity()))
            .ok_or(Error::Arithmetic)?;
        let capacity_bytes = size_of::<Collection>()
            .checked_add(heap_bytes)
            .ok_or(Error::Arithmetic)?;
        if heap_bytes != plan.heap_bytes
            || capacity_bytes != plan.capacity_bytes
            || slots.len() != count
        {
            return Err(Error::Invariant);
        }
        let instance = NEXT_COLLECTION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::Arithmetic)?;
        let usage = Usage {
            limit_bytes: limits.capacity_bytes,
            fixed_bytes: size_of::<Collection>(),
            heap_bytes,
            capacity_bytes,
            allocations,
            owners: plan.config.owners,
        };
        Ok(Self {
            plan,
            instance,
            context,
            slots,
            usage,
            raw_send,
            raw_receive,
            unreliable_statistics: UnreliableStatistics::default(),
            compact_wire: false,
        })
    }
}

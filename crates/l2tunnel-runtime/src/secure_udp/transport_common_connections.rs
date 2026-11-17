//! Original authenticated raw-ACK input custody on the sole Common loop.
use super::*;
use l2tunnel::{
    connection_records as connections, record_bank, record_configuration as configuration,
    record_engine as engine,
};

/// Explicit local storage for raw ACK inputs awaiting actual receiver custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionIngressLimits {
    /// Number of complete authenticated plaintext records retained at most.
    pub slots: usize,
    /// Full managed FIFO, metadata, free-list and payload capacity allowance.
    pub capacity_bytes: usize,
}
impl ConnectionIngressLimits {
    pub(super) fn plan(self, maximum: usize) -> io::Result<native_storage::Plan<PendingInput>> {
        if self.slots == 0 || self.capacity_bytes == 0 {
            return Err(invalid(
                "connection input custody requires positive explicit bounds",
            ));
        }
        u64::try_from(self.slots).map_err(invalid)?;
        u64::try_from(self.capacity_bytes).map_err(invalid)?;
        let bytes = self.slots.checked_mul(maximum).ok_or_else(exhausted)?;
        let plan = native_storage::Queue::plan(self.slots, bytes, maximum)?;
        if plan.capacity_bytes() > self.capacity_bytes {
            return Err(io::Error::other(l2tunnel::native_storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: self.capacity_bytes,
            }));
        }
        Ok(plan)
    }
}

/// Actual local raw input observations; no field asserts reliable or peer delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionIngressSnapshot {
    /// Exact authenticated local request.
    pub limits: ConnectionIngressLimits,
    /// Actual reserved managed heap, counted once in the external subtotal.
    pub capacity_bytes: usize,
    /// Complete retained plaintext count.
    pub packets: usize,
    /// Initialized retained plaintext bytes.
    pub bytes: usize,
    /// Actual earliest original cap across all retained inputs.
    pub deadline_micros: Option<u64>,
    /// Inputs copied into this real owner after retryable receiver pressure.
    pub retained: u64,
    /// Actual attempts against their original Reader, without re-opening Records.
    pub retried: u64,
    /// Inputs subsequently accepted by the actual Collection.
    pub admitted: u64,
    /// Unreliable inputs lost because this explicit queue was full.
    pub dropped_full: u64,
    /// Unreliable inputs lost before admission at their original hold cap.
    pub expired: u64,
}

#[derive(Clone, Copy)]
pub(super) struct PendingInput {
    scope: Scope,
    number: u64,
    received: u64,
    deadline: u64,
}

pub(super) struct Input {
    queue: native_storage::Queue<PendingInput>,
    limits: ConnectionIngressLimits,
    retained: u64,
    retried: u64,
    admitted: u64,
    dropped_full: u64,
    expired: u64,
}
impl Input {
    pub(super) fn new(
        limits: ConnectionIngressLimits,
        plan: native_storage::Plan<PendingInput>,
    ) -> io::Result<Self> {
        let capacity_bytes = plan.capacity_bytes();
        let queue = native_storage::Queue::with_plan(plan)?;
        if queue.capacity_bytes() != capacity_bytes
            || queue.capacity_bytes() > limits.capacity_bytes
        {
            return Err(invalid("connection input capacity differs from its plan"));
        }
        Ok(Self {
            queue,
            limits,
            retained: 0,
            retried: 0,
            admitted: 0,
            dropped_full: 0,
            expired: 0,
        })
    }
    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
    pub(super) fn snapshot(&self) -> ConnectionIngressSnapshot {
        ConnectionIngressSnapshot {
            limits: self.limits,
            capacity_bytes: self.queue.capacity_bytes(),
            packets: self.queue.len(),
            bytes: self.queue.bytes(),
            deadline_micros: self
                .queue
                .iter()
                .map(|packet| packet.metadata().deadline)
                .min(),
            retained: self.retained,
            retried: self.retried,
            admitted: self.admitted,
            dropped_full: self.dropped_full,
            expired: self.expired,
        }
    }
}

pub(super) fn feedback_awaiting_physical(error: &record_bank::Error) -> bool {
    let pressure = match error {
        record_bank::Error::Engine(engine::Error::Aligned(error))
        | record_bank::Error::Engine(engine::Error::Connections(connections::Error::Endpoint(
            error,
        ))) => error,
        _ => return false,
    };
    matches!(
        pressure,
        l2tunnel_aligned::Error::RecoveryPressure(l2tunnel_reliable::Error::Arq(
            recovery::RecoveryError::FeedbackAwaitingPhysical
        ))
    )
}

pub(super) fn maximum_body(
    send: connections::Direction,
    receive: connections::Direction,
) -> io::Result<usize> {
    let send_overhead = send
        .compact
        .recovery
        .outer_overhead_bytes()
        .checked_sub(connections::route::HEADER_BYTES)
        .ok_or_else(exhausted)?;
    let receive_overhead = receive
        .compact
        .recovery
        .outer_overhead_bytes()
        .checked_sub(connections::route::HEADER_BYTES)
        .ok_or_else(exhausted)?;
    let config =
        connections::Config::from_directions(send, receive, send_overhead, receive_overhead)
            .map_err(invalid)?;
    connections::storage::Plan::for_collection(config)
        .map(|plan| plan.send_max_packet_bytes())
        .map_err(invalid)
}

impl Driver {
    pub(super) fn common_original_cap(&self) -> io::Result<u64> {
        let mut cap = self.lease;
        let runtime = self
            .common
            .as_deref()
            .ok_or_else(|| protocol("Common input owner missing"))?;
        if let Some(at) = self
            .common_state()?
            .operation_deadline()
            .into_iter()
            .chain(runtime.outcome.map(common_actions::outcome_deadline))
            .min()
        {
            cap = cap.min(u64::try_from(at.as_micros()).map_err(invalid)?);
        }
        Ok(cap)
    }

    pub(super) fn connection_scope(&self, scope: Scope) -> io::Result<bool> {
        Ok(self
            .common_state()?
            .peer()
            .reader(core::Epoch(scope.epoch.0))
            .is_some_and(|reader| {
                matches!(
                    reader.config.descriptor().profile(),
                    configuration::Profile::PerConnectionCompact { .. }
                )
            }))
    }

    pub(super) fn raw_connection_deadline(&self, scope: Scope, received: u64) -> io::Result<u64> {
        let reader = self
            .common_state()?
            .peer()
            .reader(core::Epoch(scope.epoch.0))
            .ok_or_else(|| protocol("raw ACK Reader missing"))?;
        let local = reader
            .config
            .descriptor()
            .local(common_contract::mg_role(self.info.role));
        let configuration::DirectionProfile::PerConnectionCompact(receive) =
            local.receive().profile()
        else {
            return Err(protocol("raw ACK without connection owner"));
        };
        let policy = receive
            .unreliable
            .ok_or_else(|| protocol("raw ACK not selected"))?;
        Ok(received
            .checked_add(policy.hold_micros)
            .ok_or_else(exhausted)?
            .min(self.common_original_cap()?))
    }

    pub(super) fn retain_common_connection_input(
        &mut self,
        opened: record::Opened,
        received: u64,
        now: u64,
        deadline: u64,
    ) -> io::Result<()> {
        if received > now {
            return Err(protocol("raw ACK arrival is in the future"));
        }
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("raw ACK runtime missing"))?;
        let input = runtime
            .connection_input
            .as_mut()
            .ok_or_else(|| protocol("raw ACK queue not installed"))?;
        if now >= deadline {
            input.expired = input.expired.saturating_add(1);
        } else if let Some(lease) = input.queue.acquire() {
            let body = self
                .buffers
                .plain
                .get(..opened.bytes)
                .ok_or_else(|| protocol("raw ACK plaintext length"))?;
            lease.copy(
                PendingInput {
                    scope: opened.scope,
                    number: opened.number.0,
                    received,
                    deadline,
                },
                received,
                body,
            )?;
            input.retained = input.retained.saturating_add(1);
            runtime.observation_dirty = true;
            return Ok(());
        } else {
            input.dropped_full = input.dropped_full.saturating_add(1);
        }
        self.counters.native_backpressure_drops =
            self.counters.native_backpressure_drops.saturating_add(1);
        runtime.observation_dirty = true;
        Ok(())
    }

    pub(super) fn retry_common_connection_input(&mut self, now: u64) -> io::Result<()> {
        let count = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.connection_input.as_ref())
            .map_or(0, |input| input.queue.len())
            .min(usize::try_from(self.config.work.receive_packets).map_err(invalid)?);
        if count == 0 || !self.check_expiry(now)? {
            return Ok(());
        }
        for _ in 0..count {
            let Some((pending, bytes)) = self
                .common
                .as_deref()
                .and_then(|runtime| runtime.connection_input.as_ref())
                .and_then(|input| input.queue.front())
                .map(|packet| (*packet.metadata(), packet.bytes().len()))
            else {
                return Ok(());
            };
            if !self.scope_registered(pending.scope) {
                return Err(protocol("raw ACK scope retired before custody release"));
            }
            let epoch = core::Epoch(pending.scope.epoch.0);
            let reader = self
                .common_state()?
                .peer()
                .reader(epoch)
                .ok_or_else(|| protocol("raw ACK retained Reader missing"))?;
            if common_actions::common_scope(epoch, reader.config)? != pending.scope {
                return Err(protocol("raw ACK retained Reader changed"));
            }
            let width = usize::from(
                reader
                    .config
                    .descriptor()
                    .local(common_contract::mg_role(self.info.role))
                    .receive()
                    .channels(),
            );
            if now >= pending.deadline {
                let runtime = self
                    .common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("raw ACK runtime missing"))?;
                let input = runtime
                    .connection_input
                    .as_mut()
                    .ok_or_else(|| protocol("raw ACK queue missing"))?;
                input.queue.complete_front()?;
                input.expired = input.expired.saturating_add(1);
                runtime.observation_dirty = true;
                self.counters.native_backpressure_drops =
                    self.counters.native_backpressure_drops.saturating_add(1);
                continue;
            }
            if bytes > self.buffers.frame.capacity() {
                return Err(protocol("raw ACK retry scratch capacity"));
            }
            // The sole synchronous poll uses this scratch only until sealing;
            // physically held ciphertext has separate immutable Runtime.wire custody.
            self.buffers.frame.resize(bytes, 0);
            let runtime = self
                .common
                .as_deref_mut()
                .ok_or_else(|| protocol("raw ACK runtime missing"))?;
            let input = runtime
                .connection_input
                .as_mut()
                .ok_or_else(|| protocol("raw ACK queue missing"))?;
            self.buffers.frame.copy_from_slice(
                input
                    .queue
                    .front()
                    .ok_or_else(|| protocol("raw ACK front changed"))?
                    .bytes(),
            );
            input.retried = input.retried.saturating_add(1);
            runtime.observation_dirty = true;
            let owner::DataOwner::Common(state) = &mut self.owner;
            match state.entry(epoch)?.accept_authenticated_until(
                engine::Tick(pending.received),
                engine::Tick(now),
                engine::Tick(pending.deadline),
                pending.number,
                engine::EmissionKind::UnreliableNative,
                &mut self.buffers.frame,
            ) {
                Ok(()) => {
                    input.queue.complete_front()?;
                    input.admitted = input.admitted.saturating_add(1);
                    runtime.native_work[(epoch.0 % 2) as usize] = width;
                }
                Err(record_bank::Error::Engine(engine::Error::Connections(
                    connections::Error::UnreliableBusy,
                ))) => {
                    // Visit each starting input at most once. Reuse the same real
                    // queue/slab pool and retain original metadata without claiming
                    // admission or physical native completion for this move.
                    input.queue.complete_front()?;
                    let lease = input
                        .queue
                        .acquire()
                        .ok_or_else(|| protocol("raw ACK rotation lost its slab"))?;
                    lease.copy(pending, pending.received, &self.buffers.frame)?;
                }
                Err(error) => return Err(protocol(error)),
            }
        }
        Ok(())
    }
}

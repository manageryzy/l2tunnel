//! Checked, fallible backing for the existing selective-repeat engine.
//!
//! Charges are requested owned allocation layouts, not allocator overhead, RSS,
//! physical pages, clocks or a guarantee against operating-system overcommit.

use crate::{ArqConfig, RecoveryError};
use std::{alloc::Layout, fmt};

/// Heap-only backing budget for one actual recovery owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum requested metadata and persistent payload layout bytes.
    pub capacity_bytes: usize,
}

/// Validated allocation-free inventory for one bidirectional recovery engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    config: ArqConfig,
    capacity_bytes: usize,
}

impl Plan {
    /// Validate the existing ARQ contract and calculate every backing layout.
    pub fn for_arq(config: ArqConfig) -> Result<Self, Error> {
        let capacity_bytes = DuplexPlan::for_arq(config, config)?.capacity_bytes();
        Ok(Self {
            config,
            capacity_bytes,
        })
    }

    /// Exact immutable protocol settings used by this plan.
    pub fn config(&self) -> ArqConfig {
        self.config
    }

    /// Complete heap-only requested layout, including currently empty slots.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

/// Allocation-free inventory for one owner with independent directional policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DuplexPlan {
    send: ArqConfig,
    receive: ArqConfig,
    capacity_bytes: usize,
}

impl DuplexPlan {
    /// Validate complete send then receive policy before calculating actual layouts.
    pub fn for_arq(send: ArqConfig, receive: ArqConfig) -> Result<Self, Error> {
        send.validate().map_err(Error::Recovery)?;
        receive.validate().map_err(Error::Recovery)?;
        let capacity_bytes = array_bytes::<crate::arq::SendSlot>(send.send_records)?
            .checked_add(array_bytes::<crate::arq::ReceiveSlot>(
                receive.receive_records,
            )?)
            .and_then(|metadata| {
                send.send_records
                    .checked_mul(send.max_source_bytes)
                    .and_then(|send_bytes| {
                        receive
                            .receive_records
                            .checked_mul(receive.max_source_bytes)
                            .and_then(|receive_bytes| send_bytes.checked_add(receive_bytes))
                    })
                    .and_then(|payload| metadata.checked_add(payload))
            })
            .ok_or(Error::Layout)?;
        Ok(Self {
            send,
            receive,
            capacity_bytes,
        })
    }

    /// Complete immutable send data-direction policy.
    pub fn send_config(&self) -> ArqConfig {
        self.send
    }

    /// Complete immutable receive data-direction policy.
    pub fn receive_config(&self) -> ArqConfig {
        self.receive
    }

    /// Complete heap-only requested layout, including currently empty slots.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

/// Checked heap-only inventory for the explicitly selected CompactARQ owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactPlan {
    send: crate::CompactArqConfig,
    receive: crate::CompactArqConfig,
    capacity_bytes: usize,
}
impl CompactPlan {
    /// Include the actual indexed payload slots, selected metadata and all history.
    pub fn for_compact(
        send: crate::CompactArqConfig,
        receive: crate::CompactArqConfig,
    ) -> Result<Self, Error> {
        send.validate().map_err(Error::Recovery)?;
        receive.validate().map_err(Error::Recovery)?;
        let sb = send.bounds();
        let rb = receive.bounds();
        let values = [
            array_bytes::<crate::arq::SendSlot>(sb.send_records)?,
            array_bytes::<crate::arq::ReceiveSlot>(rb.receive_records)?,
            array_bytes::<u8>(sb.max_source_bytes)?
                .checked_mul(sb.send_records)
                .ok_or(Error::Layout)?,
            array_bytes::<u8>(rb.max_source_bytes)?
                .checked_mul(rb.receive_records)
                .ok_or(Error::Layout)?,
            array_bytes::<crate::arq::CompactMeta>(sb.send_records)?,
            array_bytes::<Option<crate::arq::CompactHistory>>(send.history_entries())?,
            array_bytes::<crate::arq::CompactState>(1)?,
        ];
        let capacity_bytes = values.into_iter().try_fold(0usize, |sum, value| {
            sum.checked_add(value).ok_or(Error::Layout)
        })?;
        Ok(Self {
            send,
            receive,
            capacity_bytes,
        })
    }
    /// Exact complete local sending policy.
    pub const fn send_config(&self) -> crate::CompactArqConfig {
        self.send
    }
    /// Exact complete peer data-direction policy.
    pub const fn receive_config(&self) -> crate::CompactArqConfig {
        self.receive
    }
    /// Actual requested persistent heap subtotal; excludes the inline owner.
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
}

/// Observation of actual retained backing; never accepted as allocation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Original construction limit, independent of current logical payloads.
    pub limit_bytes: usize,
    /// Actual retained requested layout, including idle payload buffers.
    pub capacity_bytes: usize,
    /// Successful explicit nonzero backing reservations, not OS allocations.
    pub allocations: usize,
}

/// Construction failures, separate from existing packet/recovery errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing configuration validation rejected the settings.
    Recovery(RecoveryError),
    /// A checked element layout or total cannot be represented.
    Layout,
    /// Complete backing exceeds the supplied heap-only budget.
    Limit {
        /// Complete required layout bytes.
        required: usize,
        /// Supplied heap-only limit bytes.
        limit: usize,
    },
    /// A fallible backing reservation failed.
    Allocation,
    /// Actual capacity differs from the validated exact inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "recovery storage error: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(crate) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}

pub(crate) struct Allocation {
    limit: usize,
    used: usize,
    allocations: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
    #[cfg(test)]
    trace: Option<ConstructionTraceHandle>,
}
impl Allocation {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            allocations: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
            #[cfg(test)]
            trace: None,
        }
    }

    pub(crate) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        let bytes = array_bytes::<T>(count)?;
        let total = self.used.checked_add(bytes).ok_or(Error::Layout)?;
        if total > self.limit {
            return Err(Error::Limit {
                required: total,
                limit: self.limit,
            });
        }
        #[cfg(test)]
        {
            self.attempts += 1;
            if self.fail_at == Some(self.attempts) {
                return Err(Error::Allocation);
            }
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if values.capacity() != count {
            return Err(Error::Invariant);
        }
        self.used = total;
        self.allocations += usize::from(bytes != 0);
        #[cfg(test)]
        if let Some(trace) = &self.trace {
            trace
                .borrow_mut()
                .record(ConstructionEventKind::Reserved, self.allocations, &values);
        }
        Ok(values)
    }

    pub(crate) fn usage(&self) -> Usage {
        Usage {
            limit_bytes: self.limit,
            capacity_bytes: self.used,
            allocations: self.allocations,
        }
    }

    #[cfg(test)]
    pub(crate) fn attempts(&self) -> usize {
        self.attempts
    }

    #[cfg(test)]
    pub(crate) fn failing(limit: usize, fail_at: usize) -> Self {
        Self {
            fail_at: Some(fail_at),
            ..Self::new(limit)
        }
    }

    #[cfg(test)]
    pub(crate) fn traced(
        limit: usize,
        fail_at: Option<usize>,
        trace: ConstructionTraceHandle,
    ) -> Self {
        Self {
            trace: Some(trace),
            fail_at,
            ..Self::new(limit)
        }
    }

    #[cfg(test)]
    pub(crate) fn trace(&self) -> Option<ConstructionTraceHandle> {
        self.trace.clone()
    }
}

// Test bookkeeping belongs to one constructor, never to a retained slot or to
// the allocator. Pointer integers identify the actual safe Vec values only.
#[cfg(test)]
pub(crate) type ConstructionTraceHandle = std::rc::Rc<std::cell::RefCell<ConstructionTrace>>;

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConstructionEventKind {
    Reserved,
    Owned,
    Released,
    Published,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ConstructionEvent {
    pub(crate) kind: ConstructionEventKind,
    pub(crate) reservation: usize,
    pub(crate) pointer: usize,
    pub(crate) capacity: usize,
    pub(crate) bytes: usize,
}

#[cfg(test)]
impl ConstructionEvent {
    pub(crate) fn for_vec<T>(
        kind: ConstructionEventKind,
        reservation: usize,
        values: &Vec<T>,
    ) -> Self {
        Self {
            kind,
            reservation,
            pointer: values.as_ptr() as usize,
            capacity: values.capacity(),
            bytes: std::mem::size_of::<T>().saturating_mul(values.capacity()),
        }
    }
}

#[cfg(test)]
pub(crate) struct ConstructionTrace {
    // Two metadata reservations plus at most64 payloads in each direction;
    // every successful reservation has reserve, ownership and terminal events.
    events: [Option<ConstructionEvent>; 3 * (2 + 64 + 64)],
    length: usize,
    pub(crate) overflow: bool,
}

#[cfg(test)]
impl Default for ConstructionTrace {
    fn default() -> Self {
        Self {
            events: [None; 3 * (2 + 64 + 64)],
            length: 0,
            overflow: false,
        }
    }
}

#[cfg(test)]
impl ConstructionTrace {
    pub(crate) fn events(&self) -> impl Iterator<Item = ConstructionEvent> + '_ {
        self.events.iter().flatten().copied()
    }

    pub(crate) fn record<T>(
        &mut self,
        kind: ConstructionEventKind,
        reservation: usize,
        values: &Vec<T>,
    ) {
        self.record_value(ConstructionEvent::for_vec(kind, reservation, values));
    }

    pub(crate) fn record_value(&mut self, event: ConstructionEvent) {
        if let Some(slot) = self.events.get_mut(self.length) {
            *slot = Some(event);
            self.length += 1;
        } else {
            self.overflow = true;
        }
    }
}

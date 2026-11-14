//! Complete actual whole-message heap inventory, including its real codec/ARQ owners.
use super::{
    Settings,
    backing::{ArrivalSlot, OutboundSlot},
    delivery,
};
use l2tunnel_codec::fragment_storage;
use l2tunnel_recovery::storage as recovery;
use std::{alloc::Layout, fmt, time::Duration};

/// Complete retained managed heap limit; excludes inline Owner and OS storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum requested retained heap layouts.
    pub capacity_bytes: usize,
}
/// Allocation-free checked full-owner inventory, not a backing permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    pub(super) settings: Settings,
    pub(super) original: usize,
    pub(super) fragments: usize,
    pub(super) batch: usize,
    pub(super) own_bytes: usize,
    capacity_bytes: usize,
    arq: recovery::Plan,
    reassembly: fragment_storage::Plan,
}
impl Plan {
    /// Preserve complete existing validation/time precedence, then calculate all heaps.
    pub fn for_owner(
        settings: Settings,
        binding: delivery::Binding,
        now: Duration,
        expires: Duration,
    ) -> Result<Self, Error> {
        let validated =
            super::validate_settings(settings, binding, now, expires).map_err(Error::Message)?;
        let arq = recovery::Plan::for_arq(settings.delivery.recovery).map_err(Error::Recovery)?;
        let reassembly = fragment_storage::Plan::for_reassembly(validated.reassembly)
            .map_err(Error::Fragment)?;
        let chunk = validated.fragmenter.chunk_bytes();
        let original = settings.max_message_bytes.min(
            chunk
                .checked_mul(usize::from(settings.max_fragments))
                .ok_or(Error::Layout)?,
        );
        let fragments = original.div_ceil(chunk);
        let batch = fragments
            .checked_mul(l2tunnel_codec::FRAGMENT_HEADER_BYTES)
            .and_then(|size| size.checked_add(original))
            .ok_or(Error::Layout)?;
        let per_slot = array_bytes::<u8>(original)?
            .checked_add(array_bytes::<u8>(batch)?)
            .and_then(|sum| sum.checked_add(array_bytes::<u64>(fragments).ok()?))
            .ok_or(Error::Layout)?;
        let own_bytes = array_bytes::<OutboundSlot>(settings.max_outbound_messages)?
            .checked_add(array_bytes::<usize>(settings.max_outbound_messages)?)
            .and_then(|sum| sum.checked_add(per_slot.checked_mul(settings.max_outbound_messages)?))
            .and_then(|sum| {
                sum.checked_add(array_bytes::<ArrivalSlot>(settings.max_incomplete_messages).ok()?)
            })
            .and_then(|sum| {
                sum.checked_add(
                    array_bytes::<u8>(settings.delivery.recovery.max_source_bytes).ok()?,
                )
            })
            .and_then(|sum| sum.checked_add(array_bytes::<u8>(settings.max_message_bytes).ok()?))
            .ok_or(Error::Layout)?;
        let capacity_bytes = own_bytes
            .checked_add(arq.capacity_bytes())
            .and_then(|sum| sum.checked_add(reassembly.capacity_bytes()))
            .ok_or(Error::Layout)?;
        Ok(Self {
            settings,
            original,
            fragments,
            batch,
            own_bytes,
            capacity_bytes,
            arq,
            reassembly,
        })
    }
    /// Complete requested managed heap, with each nested heap counted once.
    pub fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }
    /// Checked actual ARQ subset; not an additional charge.
    pub fn arq_plan(&self) -> recovery::Plan {
        self.arq
    }
    /// Checked actual reassembly subset; not an additional charge.
    pub fn reassembly_plan(&self) -> fragment_storage::Plan {
        self.reassembly
    }
}
/// Actual retained heaps, including idle slots and nested breakdowns once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Usage {
    /// Supplied full-owner heap limit.
    pub limit_bytes: usize,
    /// Actual complete retained managed heap.
    pub capacity_bytes: usize,
    /// Successful explicit nonzero reservations, including nested owners.
    pub allocations: usize,
    /// Actual included recovery subset, not an extra charge.
    pub arq: recovery::Usage,
    /// Actual included codec subset, not an extra charge.
    pub reassembly: fragment_storage::Usage,
}
/// Complete constructor errors; packet/custody errors retain their existing meanings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Existing message/service validation failed.
    Message(super::Error),
    /// Actual recovery planning/provision failed.
    Recovery(recovery::Error),
    /// Actual codec planning/provision failed.
    Fragment(fragment_storage::Error),
    /// Layout or checked arithmetic failed.
    Layout,
    /// Complete heap inventory exceeds the supplied limit.
    Limit {
        /// Full required layouts.
        required: usize,
        /// Supplied heap limit.
        limit: usize,
    },
    /// A fallible local reservation failed.
    Allocation,
    /// Actual backing differs from the checked inventory.
    Invariant,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "message storage error: {self:?}")
    }
}
impl std::error::Error for Error {}
pub(super) fn array_bytes<T>(count: usize) -> Result<usize, Error> {
    if std::mem::size_of::<T>() == 0 {
        return Err(Error::Layout);
    }
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| Error::Layout)
}
pub(super) struct Allocation {
    limit: usize,
    used: usize,
    allocations: usize,
    #[cfg(test)]
    fail_at: Option<usize>,
    #[cfg(test)]
    attempts: usize,
    #[cfg(test)]
    pub(super) trace: std::rc::Rc<std::cell::RefCell<Vec<DropEvent>>>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DropEvent {
    Before(usize),
    After(usize),
}
impl Allocation {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: 0,
            allocations: 0,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            attempts: 0,
            #[cfg(test)]
            trace: std::rc::Rc::default(),
        }
    }
    fn charge<T>(&mut self, count: usize) -> Result<usize, Error> {
        let bytes = array_bytes::<T>(count)?;
        let next = self.used.checked_add(bytes).ok_or(Error::Layout)?;
        if next > self.limit {
            return Err(Error::Limit {
                required: next,
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
        Ok(next)
    }
    pub(super) fn vec<T>(&mut self, count: usize) -> Result<Vec<T>, Error> {
        let next = self.charge::<T>(count)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        if values.capacity() != count {
            return Err(Error::Invariant);
        }
        self.used = next;
        self.allocations += usize::from(count != 0);
        Ok(values)
    }
    pub(super) fn used(&self) -> usize {
        self.used
    }
    pub(super) fn allocations(&self) -> usize {
        self.allocations
    }
    #[cfg(test)]
    pub(super) fn failing(limit: usize, point: usize) -> Self {
        Self {
            fail_at: Some(point),
            ..Self::new(limit)
        }
    }
}

//! Actual two-slot reserved record ownership; switch and physical authority stay external.
//!
//! Current/staged/draining roles belong to the runtime's existing transaction FSM.
//! Publishing a virgin owner changes no authenticated epoch or security state.

use crate::record_engine as engine;
use std::{
    mem::size_of,
    sync::atomic::{AtomicU64, Ordering},
};

mod entry;
/// Complete actual retained layout and typed construction/custody refusals.
pub mod storage;
pub use entry::{
    CarrierOutputToken, Entry, FragmentOutputToken, NativePreparation, NativeToken, PreparedNative,
};
pub use storage::Error;

#[cfg(test)]
mod carrier_tests;
#[cfg(test)]
mod storage_tests;
#[cfg(test)]
mod tests;

// Local ownership only; never serialized, authenticated or used as a nonce.
static NEXT_BANK: AtomicU64 = AtomicU64::new(1);
fn allocate_instance(next: &AtomicU64) -> Result<u64, Error> {
    next.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        current.checked_add(1)
    })
    .map_err(|_| Error::Exhausted)
}

/// Opaque local identity of one exact Bank slot and nonreusable generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationId {
    instance: u64,
    slot: usize,
    generation: u64,
}

/// Move-only guard for an actual virgin slot; dropping it does not cancel the Bank.
#[derive(Debug)]
pub struct Prepared {
    id: GenerationId,
    consumed: bool,
}

struct Slot {
    generation: u64,
    published: bool,
    heap_bytes: usize,
    allocations: usize,
    engine: engine::Engine,
}

/// Sole owner of two actual reserved Engines and their complete combined charge.
///
/// The external subtotal is caller-accounted, not an actual external reservation
/// or authenticated retirement proof. No mutable Engine or ownership escape exists.
pub struct Bank {
    instance: u64,
    initial: GenerationId,
    limits: storage::Limits,
    external_bytes: usize,
    engine_bytes: usize,
    building_bytes: usize,
    capacity_bytes: usize,
    peak_bytes: usize,
    allocations: usize,
    next_generation: Option<u64>,
    slots: [Option<Slot>; 2],
}

impl Bank {
    /// Pre-admit the entire initial layout and construct exactly one actual owner.
    pub fn new(plan: storage::Plan, limits: storage::Limits) -> Result<Self, Error> {
        Self::new_with(plan, limits, core::convert::identity)
    }

    /// Construct the same precharged Bank and transfer it directly to caller storage.
    ///
    /// The callback runs once, after initial construction succeeds. Transferring
    /// here avoids retaining large intermediate Bank return values in runtime
    /// callers while nested Engine constructors use the same thread stack.
    pub fn new_with<R>(
        plan: storage::Plan,
        limits: storage::Limits,
        finish: impl FnOnce(Self) -> R,
    ) -> Result<R, Error> {
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let base = size_of::<Self>()
            .checked_add(plan.external_bytes())
            .ok_or(Error::Layout)?;
        let instance = allocate_instance(&NEXT_BANK)?;
        let mut bank = Self {
            instance,
            initial: GenerationId {
                instance,
                slot: 0,
                generation: 1,
            },
            limits,
            external_bytes: plan.external_bytes(),
            engine_bytes: 0,
            building_bytes: 0,
            capacity_bytes: base,
            peak_bytes: base,
            allocations: 0,
            next_generation: Some(1),
            slots: [None, None],
        };
        let mut guard = bank.prepare(*plan.initial())?;
        bank.initial = bank.publish(&mut guard)?;
        Ok(finish(bank))
    }

    /// Historical original identity, not the runtime's current epoch selection.
    pub const fn initial(&self) -> GenerationId {
        self.initial
    }

    /// Construct one real virgin owner under complete precharge, without protocol admission.
    pub fn prepare(&mut self, plan: engine::storage::Plan) -> Result<Prepared, Error> {
        self.prepare_with(plan, |plan, limits, _| {
            engine::Engine::new_reserved(plan, limits)
        })
    }

    fn prepare_with(
        &mut self,
        plan: engine::storage::Plan,
        build: impl FnOnce(
            engine::storage::Plan,
            engine::storage::Limits,
            storage::Usage,
        ) -> Result<engine::Engine, engine::storage::Error>,
    ) -> Result<Prepared, Error> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Slots)?;
        let generation = self.next_generation.ok_or(Error::Exhausted)?;
        let retained = self
            .engine_bytes
            .checked_add(plan.heap_bytes())
            .ok_or(Error::Layout)?;
        let total = size_of::<Self>()
            .checked_add(self.external_bytes)
            .and_then(|bytes| bytes.checked_add(retained))
            .ok_or(Error::Layout)?;
        if total > self.limits.capacity_bytes {
            return Err(Error::Limit {
                required: total,
                limit: self.limits.capacity_bytes,
            });
        }
        let previous_charge = self.capacity_bytes;
        self.building_bytes = plan.heap_bytes();
        self.capacity_bytes = total;
        self.peak_bytes = self.peak_bytes.max(total);
        // Keep one constructed Engine until it moves into the existing inline
        // slot. Intermediate Result tuples duplicate this large owner's stack
        // extent in debug builds without providing another ownership boundary.
        let engine = match build(
            plan,
            engine::storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
            self.usage(),
        ) {
            Ok(engine) => engine,
            Err(error) => {
                self.building_bytes = 0;
                self.capacity_bytes = previous_charge;
                return Err(Error::Storage(error));
            }
        };
        let (allocations, allocation_total) =
            match observed(&engine, &plan).and_then(|allocations| {
                self.allocations
                    .checked_add(allocations)
                    .ok_or(Error::Layout)
                    .map(|total| (allocations, total))
            }) {
                Ok(counts) => counts,
                Err(error) => {
                    // Release the actual target while its full charge is retained.
                    drop(engine);
                    self.building_bytes = 0;
                    self.capacity_bytes = previous_charge;
                    return Err(error);
                }
            };
        self.slots[index] = Some(Slot {
            generation,
            published: false,
            heap_bytes: plan.heap_bytes(),
            allocations,
            engine,
        });
        self.engine_bytes = retained;
        self.allocations = allocation_total;
        self.building_bytes = 0;
        self.next_generation = generation.checked_add(1);
        Ok(Prepared {
            id: GenerationId {
                instance: self.instance,
                slot: index,
                generation,
            },
            consumed: false,
        })
    }

    /// Observe the exact retained virgin instance without allowing packet mutation.
    pub fn prepared_engine(&self, guard: &Prepared) -> Result<&engine::Engine, Error> {
        Ok(&self.prepared_slot(guard)?.engine)
    }

    /// Publish storage exactly once; this call grants no authenticated epoch authority.
    pub fn publish(&mut self, guard: &mut Prepared) -> Result<GenerationId, Error> {
        self.prepared_slot(guard)?;
        let slot = self.slots[guard.id.slot].as_mut().ok_or(Error::Stale)?;
        slot.published = true;
        guard.consumed = true;
        Ok(guard.id)
    }

    /// Release the exact untouched virgin owner only after actual local drain.
    pub fn cancel(&mut self, guard: &mut Prepared) -> Result<(), Error> {
        self.prepared_slot(guard)?;
        self.release(guard.id, false)?;
        guard.consumed = true;
        Ok(())
    }

    /// Immutable observations from an exact published owner.
    pub fn engine(&self, id: GenerationId) -> Result<&engine::Engine, Error> {
        Ok(&self.slot(id, true)?.engine)
    }

    /// Borrow only bounded packet/native methods from an exact published owner.
    pub fn entry(&mut self, id: GenerationId) -> Result<Entry<'_>, Error> {
        self.slot(id, true)?;
        let slot = self.slots[id.slot].as_mut().ok_or(Error::Stale)?;
        Ok(Entry::new(id, &mut slot.engine))
    }

    /// Release a published owner after actual pure drain; external proof stays required.
    pub fn retire(&mut self, id: GenerationId) -> Result<(), Error> {
        self.release(id, true)
    }

    fn release(&mut self, id: GenerationId, published: bool) -> Result<(), Error> {
        let slot = self.slot(id, published)?;
        if !slot.engine.drained().map_err(Error::Engine)? {
            return Err(Error::NotDrained);
        }
        let remaining = self
            .engine_bytes
            .checked_sub(slot.heap_bytes)
            .ok_or(Error::Invariant)?;
        let allocations = self
            .allocations
            .checked_sub(slot.allocations)
            .ok_or(Error::Invariant)?;
        let total = size_of::<Self>()
            .checked_add(self.external_bytes)
            .and_then(|bytes| bytes.checked_add(remaining))
            .ok_or(Error::Layout)?;
        let retired = self.slots[id.slot].take();
        drop(retired);
        self.engine_bytes = remaining;
        self.allocations = allocations;
        self.capacity_bytes = total;
        Ok(())
    }

    fn slot(&self, id: GenerationId, published: bool) -> Result<&Slot, Error> {
        if id.instance != self.instance {
            return Err(Error::Stale);
        }
        self.slots
            .get(id.slot)
            .and_then(Option::as_ref)
            .filter(|slot| slot.generation == id.generation && slot.published == published)
            .ok_or(Error::Stale)
    }
    fn prepared_slot(&self, guard: &Prepared) -> Result<&Slot, Error> {
        if guard.consumed {
            return Err(Error::Stale);
        }
        self.slot(guard.id, false)
    }

    /// Actual retained layouts and admitted attempted peak; no physical/authentication proof.
    pub fn usage(&self) -> storage::Usage {
        storage::Usage {
            limit_bytes: self.limits.capacity_bytes,
            fixed_bytes: size_of::<Self>(),
            external_bytes: self.external_bytes,
            engine_bytes: self.engine_bytes,
            building_bytes: self.building_bytes,
            capacity_bytes: self.capacity_bytes,
            peak_bytes: self.peak_bytes,
            allocations: self.allocations,
        }
    }
}

fn observed(actual: &engine::Engine, plan: &engine::storage::Plan) -> Result<usize, Error> {
    let usage = actual.storage_usage().ok_or(Error::Invariant)?;
    if usage.fixed_bytes != size_of::<engine::Engine>()
        || usage
            .pipeline_bytes
            .checked_add(usage.record_bytes)
            .and_then(|bytes| bytes.checked_add(usage.ingress_bytes))
            .and_then(|bytes| bytes.checked_add(usage.fragment_bytes))
            != Some(plan.heap_bytes())
        || usage.fixed_bytes.checked_add(plan.heap_bytes()) != Some(usage.capacity_bytes)
        || usage.capacity_bytes != plan.capacity_bytes()
        || usage.limit_bytes != plan.capacity_bytes()
        || actual.ingress_snapshot().map(|owner| owner.policy) != plan.ingress_policy()
        || actual.rolling_ingress_status().map(|owner| owner.limits)
            != plan.rolling_ingress_policy()
        || actual.fragment_policy() != plan.fragment_policy()
        || actual.configuration() != plan.configuration()
        || actual.qualification() != engine::Qualification::Reserved
    {
        return Err(Error::Invariant);
    }
    Ok(usage.allocations)
}

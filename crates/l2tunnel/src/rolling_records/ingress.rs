//! One actual bounded queue for already authenticated, replay-checked wire inputs.
use super::*;
use crate::native_storage as queue;
use record_engine::EmissionKind;

/// Explicit receive input custody, independent of coding window and carrier lanes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressLimits {
    /// Actual complete plaintext input buffers; never derived from coding support.
    pub slots: usize,
    /// Complete Queue-owned heap allowance, including idle buffers and metadata.
    pub capacity_bytes: usize,
}
#[derive(Clone, Copy)]
pub(super) struct Input {
    pub(super) kind: record_engine::EmissionKind,
    pub(super) held_source: Option<rolling::SourceId>,
    pub(super) number: Option<u64>,
    pub(super) received: Tick,
    pub(super) order: Option<codec::CausalTime>,
    pub(super) original_cap: Tick,
    pub(super) deadline: Tick,
}
/// Actual retained input state; no native, peer receipt or authentication inference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressStatus {
    /// Exact immutable selected local resource policy.
    pub limits: IngressLimits,
    /// Actual retained Queue-owned heap, including all idle buffers.
    pub capacity_bytes: usize,
    /// Actual retained nonempty Queue allocations.
    pub allocations: usize,
    /// Actual occupied FIFO packet slots.
    pub packets: usize,
    /// Actual initialized retained wire bytes.
    pub bytes: usize,
    /// Original arrival of the immutable FIFO head.
    pub oldest_received: Option<Tick>,
    /// Records number already authenticated by the caller; not replay authority.
    pub oldest_records_number: Option<u64>,
    /// Full-slot refusals for systematic sources, repairs and deferred feedback, respectively.
    pub full_refusals: [u64; 3],
    /// Earliest original queued job/operation/session cap.
    pub deadline: Option<Tick>,
}
impl IngressLimits {
    pub(super) fn plan(self, maximum: usize) -> Result<queue::Plan<Input>, Error> {
        let bytes = self.slots.checked_mul(maximum).ok_or(Error::Arithmetic)?;
        let plan = queue::Plan::for_queue(queue::Config {
            packets: self.slots,
            bytes,
            max_native: maximum,
        })
        .map_err(Error::Ingress)?;
        if plan.capacity_bytes() > self.capacity_bytes {
            return Err(Error::Ingress(queue::Error::Limit {
                required: plan.capacity_bytes(),
                limit: self.capacity_bytes,
            }));
        }
        Ok(plan)
    }
    /// Checked actual queue capacity for a complete selected receive-wire maximum.
    /// This validates all layouts and the original allowance without allocation.
    pub fn required_capacity(self, maximum: usize) -> Result<usize, Error> {
        Ok(self.plan(maximum)?.capacity_bytes())
    }
}
pub(super) struct Ingress {
    limits: IngressLimits,
    minimum: Option<Tick>,
    feedback: usize,
    full_refusals: [u64; 3],
    pub(super) waiting_on_decoder: bool,
    pub(super) queue: queue::Queue<Input>,
}
impl Ingress {
    pub(super) fn new(limits: IngressLimits, maximum: usize) -> Result<Self, Error> {
        let plan = limits.plan(maximum)?;
        let queue = queue::Queue::new_reserved(
            plan,
            queue::Limits {
                capacity_bytes: limits.capacity_bytes,
            },
        )
        .map_err(Error::Ingress)?;
        Ok(Self {
            limits,
            queue,
            minimum: None,
            feedback: 0,
            full_refusals: [0; 3],
            waiting_on_decoder: false,
        })
    }
    pub(super) fn status(&self) -> IngressStatus {
        IngressStatus {
            limits: self.limits,
            capacity_bytes: self.usage().capacity_bytes,
            allocations: self.usage().allocations,
            packets: self.queue.len(),
            bytes: self.queue.bytes(),
            oldest_received: self.queue.front().map(|packet| packet.metadata().received),
            oldest_records_number: self
                .queue
                .front()
                .and_then(|packet| packet.metadata().number),
            deadline: self.deadline(),
            full_refusals: self.full_refusals,
        }
    }
    pub(super) fn deadline(&self) -> Option<Tick> {
        self.minimum
    }
    pub(super) fn push(&mut self, input: Input, bytes: &[u8]) -> Result<(), Error> {
        let Some(slot) = self.queue.acquire() else {
            let index = match input.kind {
                EmissionKind::Source(_) => 0,
                EmissionKind::Repair => 1,
                EmissionKind::Feedback => 2,
                _ => return Err(Error::Identity),
            };
            self.full_refusals[index] = self.full_refusals[index].saturating_add(1);
            return Err(Error::Busy);
        };
        slot.copy(input, input.received.0, bytes)
            .map_err(Error::Ingress)?;
        self.minimum = Some(
            self.minimum
                .map_or(input.deadline, |old| old.min(input.deadline)),
        );
        self.feedback += usize::from(input.kind == record_engine::EmissionKind::Feedback);
        Ok(())
    }
    pub(super) fn has_feedback(&self) -> bool {
        self.feedback != 0
    }
    pub(super) fn has_data(&self) -> bool {
        self.queue.len() > self.feedback
    }
    pub(super) fn complete_front(&mut self) -> Result<(), Error> {
        let input = *self.queue.front().ok_or(Error::Identity)?.metadata();
        self.queue.complete_front().map_err(Error::Ingress)?;
        self.feedback -= usize::from(input.kind == record_engine::EmissionKind::Feedback);
        if self.minimum == Some(input.deadline) {
            self.minimum = self
                .queue
                .iter()
                .map(|packet| packet.metadata().deadline)
                .min();
        }
        Ok(())
    }
    pub(super) fn usage(&self) -> queue::Usage {
        self.queue.storage_usage()
    }
}

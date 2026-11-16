//! Actual optional ACK custody attached to this exact Engine's Pipeline.
use super::*;
use pipeline::ack_coalescing as ack;

pub use ack::Admission as IngressAdmission;

/// Local real owner observations; not endpoint ACK generation or remote authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressSnapshot {
    /// Exact installed immutable selection.
    pub policy: ack::Policy,
    /// Actual retained layouts and logical originals still held here.
    pub usage: ack::Usage,
    /// Actual observed coalescing/forwarding events.
    pub statistics: ack::Statistics,
    /// Original earliest hard expiry, never a renewed retry timer.
    pub expiry: Option<Tick>,
}
impl Engine {
    /// Consume only on an explicit typed success. A held ACK has no Pipeline ID.
    /// Errors retain the new input; an older held original may already have moved.
    pub fn ingest_borrowed(
        &mut self,
        now: Tick,
        bytes: &[u8],
        original_cap: Tick,
    ) -> Result<IngressAdmission, Error> {
        self.ingest_borrowed_at(now, now, bytes, original_cap)
    }
    /// Preserve original read time while retrying against the current injected clock.
    pub fn ingest_borrowed_at(
        &mut self,
        received: Tick,
        now: Tick,
        bytes: &[u8],
        original_cap: Tick,
    ) -> Result<IngressAdmission, Error> {
        self.advance(now)?;
        if let Some(ingress) = &mut self.ingress {
            ingress
                .ingest_at(
                    &mut self.pipeline,
                    bytes,
                    duration(received),
                    duration(now),
                    duration(original_cap),
                )
                .map_err(Error::Ingress)
        } else {
            let admitted = if self.requires_original_ingress_cap() {
                self.pipeline.enqueue_borrowed_capped(
                    bytes,
                    duration(received),
                    duration(now),
                    duration(original_cap),
                )
            } else {
                self.pipeline.enqueue_borrowed(bytes, duration(now))
            };
            admitted
                .map(IngressAdmission::Forwarded)
                .map_err(Error::Pipeline)
        }
    }
    /// Service at most the explicit number of real ingress slots, without hidden work.
    pub fn service_ingress(
        &mut self,
        now: Tick,
        draining: bool,
        work: usize,
    ) -> Result<ack::Progress, Error> {
        self.advance(now)?;
        let Some(ingress) = &mut self.ingress else {
            return Ok(ack::Progress::default());
        };
        match ingress.advance(&mut self.pipeline, duration(now), draining, work) {
            Ok(progress) => Ok(progress),
            Err(error) => self.fail(Error::Ingress(error)),
        }
    }
    /// True only when this generation retains no unsent coalescing candidate.
    pub fn ingress_empty(&self) -> bool {
        self.ingress.as_ref().is_none_or(ack::Ingress::is_empty)
    }
    /// Retire matching history only after actual common/profile custody is drained.
    /// This conservative shared-owner proof is stronger than per-flow queue emptiness.
    pub fn retire_ingress_flow(
        &mut self,
        now: Tick,
        key: &pipeline::FlowKey,
    ) -> Result<pipeline::Binding, Error> {
        if matches!(&self.owner, Owner::Connections(_)) {
            return Err(Error::Unsupported(Capability::FlowReuse));
        }
        self.advance(now)?;
        if self.pending.is_some() || !self.owner.drained()? {
            return Err(Error::Ingress(ack::Error::Busy));
        }
        if let Some(ingress) = &mut self.ingress {
            ingress
                .retire_drained(&mut self.pipeline, key)
                .map_err(Error::Ingress)
        } else {
            self.pipeline.retire_drained(key).map_err(Error::Pipeline)
        }
    }
    /// Observe the actual installed owner, never the requested policy as installed.
    pub fn ingress_snapshot(&self) -> Option<IngressSnapshot> {
        self.ingress.as_ref().map(|ingress| IngressSnapshot {
            policy: ingress.policy(),
            usage: ingress.usage(),
            statistics: ingress.statistics(),
            expiry: self.ingress_expiry(),
        })
    }
    /// Bound a past due blocked candidate by the existing caller-supplied cadence.
    pub fn ingress_wake_at(&self, now: Tick, cadence: Duration) -> Result<Option<Tick>, Error> {
        self.healthy()?;
        self.ingress
            .as_ref()
            .map(|ingress| {
                ingress
                    .wake_at(duration(now), cadence)
                    .map_err(Error::Ingress)
                    .and_then(|at| {
                        at.map(|at| {
                            u64::try_from(at.as_micros())
                                .map(Tick)
                                .map_err(|_| Error::Time)
                        })
                        .transpose()
                    })
            })
            .transpose()
            .map(Option::flatten)
    }
    pub(super) fn ingress_expiry(&self) -> Option<Tick> {
        self.ingress
            .as_ref()
            .and_then(|ingress| ingress.pending().map(|p| p.expires).min())
            .map(|at| Tick(u64::try_from(at.as_micros()).unwrap_or(u64::MAX)))
    }
}

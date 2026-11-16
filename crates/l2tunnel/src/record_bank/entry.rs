#[path = "fragment.rs"]
mod fragment;
use super::{Error, GenerationId, engine};
pub use fragment::FragmentOutputToken;
use l2tunnel_codec::aligned_receiver::UnitWitness;
use l2tunnel_pipeline::{Admission, PacketMetadata};
use l2tunnel_reliable::OutboundBudget;

/// Move-only actual pending carrier witness bound to its issuing Bank generation.
/// This token does not prove physical completion; the caller must observe it.
#[derive(Debug, Eq, PartialEq)]
pub struct CarrierOutputToken {
    generation: GenerationId,
    token: engine::CarrierOutputToken,
}

impl CarrierOutputToken {
    /// Exact issuing Bank, slot and nonreusable generation.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    /// Actual record emission whose whole carrier ownership is still pending.
    pub fn emission(&self) -> engine::Emission {
        self.token.emission()
    }

    /// Original exact Engine context; this public label is not authentication.
    pub fn context(&self) -> engine::Context {
        self.token.context()
    }
}

/// Exact local generation plus the original actual Engine completion token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeToken {
    generation: GenerationId,
    token: engine::NativeToken,
}

/// Immutable actual native handoff metadata bound to its issuing Bank generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedNative {
    generation: GenerationId,
    prepared: engine::PreparedNative,
}
impl PreparedNative {
    /// Exact issuing Bank and slot generation.
    pub const fn generation(self) -> GenerationId {
        self.generation
    }
    /// Original completion token plus its exact generation binding.
    pub const fn token(self) -> NativeToken {
        NativeToken {
            generation: self.generation,
            token: self.prepared.token(),
        }
    }
    /// Actual maintained profile identity, not a native count prefix.
    pub const fn identity(self) -> engine::ProfileIdentity {
        self.prepared.identity()
    }
    /// Initialized native bytes retained in the caller's output slot.
    pub const fn bytes(self) -> usize {
        self.prepared.bytes()
    }
    /// Actual early-delivery status.
    pub const fn early(self) -> bool {
        self.prepared.early()
    }
    /// Original immutable actual completion deadline.
    pub const fn deadline(self) -> engine::Tick {
        self.prepared.deadline()
    }
}

/// Actual finite native preparation result, without another payload owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePreparation {
    /// No eligible packet on the visited channel.
    Idle,
    /// Actual receiver context/tombstone progress without a physical packet.
    Progress,
    /// New actual immutable packet in the caller's retained output slot.
    Ready(PreparedNative),
    /// The existing caller-owned packet remains pending without output overwrite.
    AlreadyPending(PreparedNative),
}

/// Restricted mutable packet methods, without extraction or replacement of an Engine.
pub struct Entry<'a> {
    generation: GenerationId,
    engine: &'a mut engine::Engine,
}
impl<'a> Entry<'a> {
    pub(super) fn new(generation: GenerationId, engine: &'a mut engine::Engine) -> Self {
        Self { generation, engine }
    }

    /// Exact issuing Bank generation; a copied ID confers no physical authority.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }
    /// Typed optional ingress admission through this generation's actual Pipeline.
    pub fn ingest_borrowed(
        &mut self,
        now: engine::Tick,
        bytes: &[u8],
        original_cap: engine::Tick,
    ) -> Result<engine::IngressAdmission, Error> {
        self.engine
            .ingest_borrowed(now, bytes, original_cap)
            .map_err(Error::Engine)
    }
    /// Retain the original input observation through delayed same-owner admission.
    pub fn ingest_borrowed_at(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        bytes: &[u8],
        original_cap: engine::Tick,
    ) -> Result<engine::IngressAdmission, Error> {
        self.engine
            .ingest_borrowed_at(received, now, bytes, original_cap)
            .map_err(Error::Engine)
    }
    /// Bounded optional ingress work against this exact generation's Pipeline.
    pub fn service_ingress(
        &mut self,
        now: engine::Tick,
        draining: bool,
        work: usize,
    ) -> Result<l2tunnel_pipeline::ack_coalescing::Progress, Error> {
        self.engine
            .service_ingress(now, draining, work)
            .map_err(Error::Engine)
    }
    /// Retire an actual drained flow and its matching optional ingress history.
    pub fn retire_ingress_flow(
        &mut self,
        now: engine::Tick,
        key: &l2tunnel_pipeline::FlowKey,
    ) -> Result<l2tunnel_pipeline::Binding, Error> {
        self.engine
            .retire_ingress_flow(now, key)
            .map_err(Error::Engine)
    }
    /// Borrow original input through the actual reserved common queue policy.
    pub fn enqueue_borrowed(
        &mut self,
        now: engine::Tick,
        bytes: &[u8],
    ) -> Result<PacketMetadata, Error> {
        self.engine
            .enqueue_borrowed(now, bytes)
            .map_err(Error::Engine)
    }
    /// Admit an already-arbitrated opaque proxy record with its original cap.
    pub fn enqueue_proxy_borrowed(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        bytes: &[u8],
        original_deadline: engine::Tick,
    ) -> Result<PacketMetadata, Error> {
        self.engine
            .enqueue_proxy_borrowed(received, now, bytes, original_deadline)
            .map_err(Error::Engine)
    }
    /// Admit one actual selected original without allocating an owned output.
    pub fn admit_borrowed(
        &mut self,
        now: engine::Tick,
    ) -> Result<Option<Admission<engine::ProfileIdentity>>, Error> {
        self.engine.admit_borrowed(now).map_err(Error::Engine)
    }
    /// Produce exact typed records under the one external shared wire allowance.
    pub fn poll(
        &mut self,
        now: engine::Tick,
        security_number: u64,
        allow_data: bool,
        output: &mut [u8],
        budget: &mut OutboundBudget,
        witnesses: &mut [UnitWitness],
    ) -> Result<Option<engine::Emission>, Error> {
        self.engine
            .poll(now, security_number, allow_data, output, budget, witnesses)
            .map_err(Error::Engine)
    }
    /// Apply exact externally authenticated, replay-checked and scoped plaintext.
    pub fn accept_authenticated(
        &mut self,
        now: engine::Tick,
        security_number: u64,
        kind: engine::EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        self.engine
            .accept_authenticated(now, security_number, kind, body)
            .map_err(Error::Engine)
    }
    /// Retry exact authenticated plaintext with its immutable original arrival.
    /// This forwards to the same actual generation and creates no new proof.
    pub fn accept_authenticated_at(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        security_number: u64,
        kind: engine::EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        self.engine
            .accept_authenticated_at(received, now, security_number, kind, body)
            .map_err(Error::Engine)
    }
    /// Retain Research feedback in the issuing generation's actual input queue.
    #[allow(clippy::too_many_arguments)] // Preserve original authenticated and causal facts.
    pub fn retain_research_feedback_authenticated_until(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        cap: engine::Tick,
        number: u64,
        order: Option<crate::codec::CausalTime>,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        self.engine
            .retain_research_feedback_authenticated_until(received, now, cap, number, order, bytes)
            .map_err(Error::Engine)
    }
    /// Preserve the authenticated input's original operation/session deadline.
    pub fn accept_authenticated_until(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        original_deadline: engine::Tick,
        security_number: u64,
        kind: engine::EmissionKind,
        body: &mut [u8],
    ) -> Result<(), Error> {
        self.engine
            .accept_authenticated_until(
                received,
                now,
                original_deadline,
                security_number,
                kind,
                body,
            )
            .map_err(Error::Engine)
    }
    /// Service actual injected deadlines without reading a real clock.
    pub fn tick(&mut self, now: engine::Tick) -> Result<(), Error> {
        self.engine.tick(now).map_err(Error::Engine)
    }
    /// Observe the actual pending carrier handoff without confirming encoded bytes.
    pub fn pending_carrier_output(&self) -> Option<CarrierOutputToken> {
        self.engine
            .pending_carrier_output()
            .map(|token| CarrierOutputToken {
                generation: self.generation,
                token,
            })
    }
    /// Confirm only a whole observed carrier handoff by the exact issuing owner.
    /// A foreign/recycled generation refuses before advancing the actual Engine time.
    pub fn confirm_carrier_output(
        &mut self,
        now: engine::Tick,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        self.confirm_carrier_output_at(now, now, token)
    }
    /// Preserve actual acceptance separately from asynchronous observation.
    /// Aligned/Packed timers use acceptance; generation custody remains exact.
    pub fn confirm_carrier_output_at(
        &mut self,
        now: engine::Tick,
        accepted: engine::Tick,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        if token.generation != self.generation {
            return Err(Error::Stale);
        }
        self.engine
            .confirm_carrier_output_at(now, accepted, token.token)
            .map_err(Error::Engine)
    }
    /// Preserve exact local receipt order for the same actual Engine witness.
    pub fn confirm_carrier_output_ordered_at(
        &mut self,
        now: engine::Tick,
        accepted: engine::Tick,
        order: crate::codec::CausalTime,
        token: CarrierOutputToken,
    ) -> Result<(), Error> {
        if token.generation != self.generation {
            return Err(Error::Stale);
        }
        self.engine
            .confirm_carrier_output_ordered_at(now, accepted, order, token.token)
            .map_err(Error::Engine)
    }
    /// Advance actual rolling work only within the caller's explicit GF/copy/visit caps.
    /// Other profile families return no rolling result and retain their own service.
    pub fn step(
        &mut self,
        now: engine::Tick,
        work: l2tunnel_fec::rolling::WorkBudget,
    ) -> Result<Option<crate::rolling_records::Step>, Error> {
        self.engine.step(now, work).map_err(Error::Engine)
    }
    /// Actual packing/tail/feedback trigger, independent of an original expiry cap.
    pub fn wake_at(&self) -> Result<Option<engine::Tick>, Error> {
        self.engine.wake_at().map_err(Error::Engine)
    }
    /// Prepare into the caller's real free slot while retaining original age and identity.
    pub fn prepare_native(
        &mut self,
        now: engine::Tick,
        work: usize,
        original_deadline: engine::Tick,
        output: &mut [u8],
    ) -> Result<NativePreparation, Error> {
        self.engine
            .prepare_native(now, work, original_deadline, output)
            .map(|result| match result {
                engine::NativePreparation::Idle => NativePreparation::Idle,
                engine::NativePreparation::Progress => NativePreparation::Progress,
                engine::NativePreparation::Ready(prepared) => {
                    NativePreparation::Ready(PreparedNative {
                        generation: self.generation,
                        prepared,
                    })
                }
                engine::NativePreparation::AlreadyPending(prepared) => {
                    NativePreparation::AlreadyPending(PreparedNative {
                        generation: self.generation,
                        prepared,
                    })
                }
            })
            .map_err(Error::Engine)
    }
    /// Observe the exact actual pending handoff without duplicating payload custody.
    pub fn pending_native(&self) -> Option<PreparedNative> {
        self.engine.pending_native().map(|prepared| PreparedNative {
            generation: self.generation,
            prepared,
        })
    }
    /// Commit only after a whole physical write, using the exact issuing generation.
    pub fn commit_native(&mut self, now: engine::Tick, token: NativeToken) -> Result<(), Error> {
        if token.generation != self.generation {
            return Err(Error::Stale);
        }
        self.engine
            .commit_native(now, token.token)
            .map_err(Error::Engine)
    }
}

impl Entry<'_> {
    /// Drive the exact retained same-generation operation on this actual Engine.
    pub fn progress_connection_reuse(
        &mut self,
        state: &mut engine::connection_reuse::ConnectionReuse,
        now: engine::Tick,
    ) -> Result<(), Error> {
        state.progress(self.engine, now).map_err(Error::Engine)
    }
}

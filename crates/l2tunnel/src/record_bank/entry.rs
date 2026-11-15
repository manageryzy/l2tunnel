use super::{Error, GenerationId, engine};
use l2tunnel_codec::aligned_receiver::UnitWitness;
use l2tunnel_pipeline::{Admission, PacketMetadata};
use l2tunnel_reliable::OutboundBudget;

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
    /// Service actual injected deadlines without reading a real clock.
    pub fn tick(&mut self, now: engine::Tick) -> Result<(), Error> {
        self.engine.tick(now).map_err(Error::Engine)
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

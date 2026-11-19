//! Generation-bound forwarding to the same actual Engine fragment owners.
use super::*;

/// Move-only physical fragment witness plus its exact issuing Bank generation.
#[derive(Debug, Eq, PartialEq)]
pub struct FragmentOutputToken {
    generation: GenerationId,
    token: engine::FragmentOutputToken,
}
impl FragmentOutputToken {
    /// Whether the negotiated group is an eight-source forward repair.
    pub fn is_near8(&self) -> bool {
        self.token.is_near8()
    }
    /// Whether this group's first copy is still held by the FEC sender.
    pub fn owns_first_original(&self) -> bool {
        self.token.owns_first_original()
    }
    /// Exact issuing Bank/slot/nonreusable generation.
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }
    /// Full actual Engine scope; the LX label is not authority.
    pub fn context(&self) -> engine::Context {
        self.token.context()
    }
    /// Exact retained physical emission, including its unchanged caller PN.
    pub fn emission(&self) -> engine::FragmentEmission {
        self.token.emission()
    }
}
impl Entry<'_> {
    /// Exact active selected fragment policy, without an installation claim.
    pub fn fragment_policy(&self) -> Option<engine::FragmentPolicy> {
        self.engine.fragment_policy()
    }
    /// Exact actual per-kind original completion custody.
    pub fn fragment_ingress_snapshot(&self) -> Option<engine::FragmentIngressSnapshot> {
        self.engine.fragment_ingress_snapshot()
    }
    /// Actual group/physical counters, distinct from native delivery.
    pub fn fragment_statistics(&self) -> Option<engine::FragmentStatistics> {
        self.engine.fragment_statistics()
    }
    /// Reserve whole group packets/bytes once from the shared external budget.
    pub fn reserve_fragment_group(
        &mut self,
        now: engine::Tick,
        prospective_number: u64,
        allow_data: bool,
        budget: &mut OutboundBudget,
        witnesses: &mut [UnitWitness],
    ) -> Result<Option<engine::FragmentGroup>, Error> {
        self.engine
            .reserve_fragment_group(now, prospective_number, allow_data, budget, witnesses)
            .map_err(Error::Engine)
    }
    /// Keep the original operation/session cap across all physical fragments.
    #[allow(clippy::too_many_arguments)] // Exact external cap extends existing output inputs.
    pub fn reserve_fragment_group_until(
        &mut self,
        now: engine::Tick,
        prospective_number: u64,
        allow_data: bool,
        original_cap: engine::Tick,
        budget: &mut OutboundBudget,
        witnesses: &mut [UnitWitness],
    ) -> Result<Option<engine::FragmentGroup>, Error> {
        self.engine
            .reserve_fragment_group_until(
                now,
                prospective_number,
                allow_data,
                original_cap,
                budget,
                witnesses,
            )
            .map_err(Error::Engine)
    }
    /// Emit one already reserved physical fragment; there is no second budget debit.
    pub fn poll_reserved_fragment(
        &mut self,
        now: engine::Tick,
        fresh_number: u64,
        output: &mut [u8],
    ) -> Result<Option<engine::FragmentEmission>, Error> {
        self.engine
            .poll_reserved_fragment(now, fresh_number, output)
            .map_err(Error::Engine)
    }
    /// Observe the actual pending logical reservation without another ID/debit.
    pub fn pending_fragment_group(&self) -> Option<engine::FragmentGroup> {
        self.engine.pending_fragment_group()
    }
    /// Exact issuing generation wraps the actual move-only physical witness.
    pub fn pending_fragment_output(&self) -> Option<FragmentOutputToken> {
        self.engine
            .pending_fragment_output()
            .map(|token| FragmentOutputToken {
                generation: self.generation,
                token,
            })
    }
    /// Only a matching generation may consume one whole physical receipt.
    pub fn confirm_fragment_at(
        &mut self,
        now: engine::Tick,
        accepted: engine::Tick,
        token: FragmentOutputToken,
    ) -> Result<engine::FragmentReceipt, Error> {
        if token.generation != self.generation {
            return Err(Error::Stale);
        }
        self.engine
            .confirm_fragment_at(now, accepted, token.token)
            .map_err(Error::Engine)
    }
    /// Forward exact original clock precision without changing physical custody.
    pub fn confirm_fragment_ordered_at(
        &mut self,
        now: engine::Tick,
        accepted: engine::Tick,
        order: crate::codec::CausalTime,
        token: FragmentOutputToken,
    ) -> Result<engine::FragmentReceipt, Error> {
        if token.generation != self.generation {
            return Err(Error::Stale);
        }
        self.engine
            .confirm_fragment_ordered_at(now, accepted, order, token.token)
            .map_err(Error::Engine)
    }
    /// Derive kind from every authenticated LX fragment under exact selected labels.
    pub fn inspect_fragment_kind(&self, bytes: &[u8]) -> Result<engine::EmissionKind, Error> {
        self.engine
            .inspect_fragment_kind(bytes)
            .map_err(Error::Engine)
    }
    /// Forward already authenticated/replay-checked plaintext with original age/cap.
    pub fn accept_fragment_authenticated_until(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        cap: engine::Tick,
        number: u64,
        bytes: &[u8],
    ) -> Result<engine::FragmentAdmission, Error> {
        self.engine
            .accept_fragment_authenticated_until(received, now, cap, number, bytes)
            .map_err(Error::Engine)
    }
    /// Preserve precise complete-body causal order through the same reassembler.
    #[allow(clippy::too_many_arguments)] // Exact arrival order extends the established age/cap inputs.
    pub fn accept_fragment_authenticated_ordered_until(
        &mut self,
        received: engine::Tick,
        now: engine::Tick,
        cap: engine::Tick,
        number: u64,
        order: crate::codec::CausalTime,
        bytes: &[u8],
    ) -> Result<engine::FragmentAdmission, Error> {
        self.engine
            .accept_fragment_authenticated_ordered_until(received, now, cap, number, order, bytes)
            .map_err(Error::Engine)
    }
    /// Retry only the three actual retained completion slots; feedback goes first.
    pub fn retry_fragment_inputs(&mut self, now: engine::Tick) -> Result<usize, Error> {
        self.engine
            .retry_fragment_inputs(now)
            .map_err(Error::Engine)
    }
}

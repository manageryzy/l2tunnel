use crate::{
    BlockConfig, Error, FecContext, GenerationId, SymbolId, SymbolView, field, inspect,
    original_length,
};
use std::collections::BTreeMap;

pub(crate) mod backing;
mod transaction;
use backing::{Basis, Generations, History, Terminals};

/// Hard live-generation count ceiling.
pub const MAX_GENERATIONS: usize = 64;
/// Hard distinct accepted symbol identities per generation.
pub const MAX_SYMBOLS_PER_GENERATION: usize = 1024;
/// Hard logical matrix/history/output reservation ceiling, excluding metadata.
pub const MAX_RESERVED_BYTES: usize = 256 * 1024 * 1024;

/// Local receiver bounds; no packet may increase them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecoderConfig {
    /// Shared dimensional, packet and per-input arithmetic limits.
    pub block: BlockConfig,
    /// Maximum live incomplete or complete-but-undelivered generations, 1..64.
    pub max_generations: usize,
    /// Maximum distinct accepted IDs per generation, including dependent rows.
    pub max_symbols_per_generation: usize,
    /// Logical byte reservation cap for matrices, exact history and output scratch.
    pub max_reserved_bytes: usize,
    /// Nonrenewable lifetime starting at the first accepted symbol, in caller ticks.
    pub max_lifetime_ticks: u64,
    /// Acceptance/terminal-history window of generation IDs, 1..4096.
    pub generation_window: u64,
}

impl DecoderConfig {
    /// Validate the existing scalar decoder contract without constructing state.
    pub fn validate(self) -> Result<(), Error> {
        self.block.validate()?;
        if !(1..=MAX_GENERATIONS).contains(&self.max_generations)
            || !(self.block.max_sources..=MAX_SYMBOLS_PER_GENERATION)
                .contains(&self.max_symbols_per_generation)
            || !(1..=MAX_RESERVED_BYTES).contains(&self.max_reserved_bytes)
            || self.max_lifetime_ticks == 0
            || !(1..=4096).contains(&self.generation_window)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }

    fn reservation(self, count: usize, width: usize) -> Result<usize, Error> {
        count
            .checked_mul(3)
            .and_then(|n| n.checked_add(self.max_symbols_per_generation))
            .and_then(|n| n.checked_mul(count.checked_add(width)?))
            .ok_or(Error::Arithmetic)
    }
}

/// Exact existing capacity gate that refused one canonically validated symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecoderCapacity {
    /// Accepted symbol identities in this live generation are full.
    SymbolSlots,
    /// Live incomplete/undelivered generation slots are full.
    GenerationSlots,
    /// The new generation would exceed the logical reservation budget.
    LogicalReservation,
}
/// Read-only aggregate gauges; no retained row is decoded or copied.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecoderBuffers {
    /// Actual live generation count.
    pub generations: usize,
    /// Negotiated live-generation bound.
    pub generations_capacity: usize,
    /// Current conservative logical reservation for live generations.
    pub logical_reservation_bytes: usize,
    /// Negotiated logical reservation cap; distinct from allocated backing.
    pub logical_reservation_capacity: usize,
    /// Existing explicit backing capacity; absent for unreserved construction.
    pub allocated_capacity_bytes: Option<usize>,
    /// Sum of actual independent rows across live generations.
    pub basis_rows: usize,
    /// Maximum retained independent rows across all configured slots.
    pub basis_rows_capacity: usize,
    /// Actual distinct received symbols, including dependent equations.
    pub history_symbols: usize,
    /// Maximum distinct-symbol slots across all configured generations.
    pub history_symbols_capacity: usize,
    /// Full-rank generations still awaiting explicit decoded retirement.
    pub completed_generations: usize,
}

/// Accepted equation's effect; completion is retained until take_decoded succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptStatus {
    /// A new independent equation increased rank but did not complete the block.
    Innovative(Progress),
    /// A distinct equation was consistent but added no independent information.
    Dependent(Progress),
    /// The exact same symbol ID, coefficients and coded bytes were already received.
    Duplicate(Progress),
    /// Every source is uniquely recovered and canonical, awaiting retrieval.
    Complete(Progress),
}

/// Current bounded generation progress; no probabilistic recovery claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Scoped generation identity.
    pub generation: GenerationId,
    /// Independent received equations.
    pub rank: usize,
    /// Independent equations required to recover every source.
    pub required_rank: usize,
    /// Distinct accepted symbol IDs, including consistent dependent inputs.
    pub received_symbols: usize,
}

/// Complete original source vectors, reconstructed solely from received payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedBlock {
    /// Delivered generation identity.
    pub generation: GenerationId,
    /// Exact source payloads in ascending source-index order, with padding removed.
    pub sources: Vec<Vec<u8>>,
}

/// Explicit deadline result, preserving rank shortage instead of claiming delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiredGeneration {
    /// Generation whose retained state was removed.
    pub generation: GenerationId,
    /// Rank at expiry; may be full if the caller did not retrieve output in time.
    pub rank: usize,
    /// Rank needed for complete payload recovery.
    pub required_rank: usize,
}

#[derive(Clone, Eq, PartialEq)]
struct Row {
    coefficients: Vec<u8>,
    payload: Vec<u8>,
}

impl Row {
    fn empty() -> Self {
        Self {
            coefficients: Vec::new(),
            payload: Vec::new(),
        }
    }
    fn clear(&mut self) {
        self.coefficients.clear();
        self.payload.clear();
    }

    fn eliminate(&mut self, row: &Self, factor: u8) {
        for (target, coefficient) in self.coefficients.iter_mut().zip(&row.coefficients) {
            *target ^= field::multiply(factor, *coefficient);
        }
        for (target, value) in self.payload.iter_mut().zip(&row.payload) {
            *target ^= field::multiply(factor, *value);
        }
    }

    fn normalize(&mut self, pivot: usize) -> Result<(), Error> {
        let factor = field::inverse(*self.coefficients.get(pivot).ok_or(Error::Arithmetic)?)
            .ok_or(Error::InvalidCoefficients)?;
        for value in self.coefficients.iter_mut().chain(&mut self.payload) {
            *value = field::multiply(factor, *value);
        }
        Ok(())
    }

    fn validate_identifiable(&self) -> Result<(), Error> {
        if self
            .coefficients
            .iter()
            .filter(|&&coefficient| coefficient != 0)
            .count()
            == 1
        {
            original_length(&self.payload)?;
        }
        Ok(())
    }
}

struct Generation {
    count: usize,
    width: usize,
    deadline: u64,
    reservation: usize,
    basis: Basis,
    received: History,
    rank: usize,
}

impl Generation {
    fn progress(&self, generation: GenerationId) -> Progress {
        Progress {
            generation,
            rank: self.rank,
            required_rank: self.count,
            received_symbols: self.received.len(),
        }
    }
}

#[derive(Clone, Copy)]
enum Terminal {
    Delivered,
    Expired,
}

/// Bounded decoder for one authenticated session/epoch/channel/direction domain.
///
/// It has no sender ledger. Enclosing authentication/replay/rate limits belong
/// to the caller. Generation identities may not be reused in this context.
pub struct Decoder {
    context: FecContext,
    config: DecoderConfig,
    generations: Generations,
    terminal: Terminals,
    work: transaction::Work,
    usage: Option<crate::storage::Usage>,
    highest: Option<GenerationId>,
    reserved: usize,
    last_now: u64,
}

impl Decoder {
    /// Validate all local caps before accepting any packet-derived allocation.
    pub fn new(context: FecContext, config: DecoderConfig) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self {
            context,
            config,
            generations: Generations::Legacy(BTreeMap::new()),
            terminal: Terminals::Legacy(BTreeMap::new()),
            work: transaction::Work::legacy(),
            usage: None,
            highest: None,
            reserved: 0,
            last_now: 0,
        })
    }

    /// Provision the complete actual decoder before accepting any packet.
    pub fn new_reserved(
        context: FecContext,
        config: DecoderConfig,
        limits: crate::storage::Limits,
    ) -> Result<Self, crate::storage::Error> {
        let plan = crate::storage::DecoderPlan::for_decoder(config)?;
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(crate::storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let mut allocation = crate::storage::Allocation::new(limits.capacity_bytes);
        Self::reserved_with(context, config, plan, &mut allocation)
    }
    pub(crate) fn reserved_with(
        context: FecContext,
        config: DecoderConfig,
        plan: crate::storage::DecoderPlan,
        allocation: &mut crate::storage::Allocation,
    ) -> Result<Self, crate::storage::Error> {
        let (generations, terminal, work) = backing::reserved(config, allocation)?;
        let usage = allocation.usage();
        if usage.capacity_bytes != plan.capacity_bytes() {
            return Err(crate::storage::Error::Invariant);
        }
        Ok(Self {
            context,
            config,
            generations,
            terminal,
            work,
            usage: Some(usage),
            highest: None,
            reserved: 0,
            last_now: 0,
        })
    }
    /// Actual retained backing; legacy construction has no reservation claim.
    pub fn storage_usage(&self) -> Option<crate::storage::Usage> {
        self.usage
    }
    #[cfg(test)]
    pub(crate) fn transaction_rows_used(&self) -> usize {
        self.work.rows_used()
    }
    #[cfg(test)]
    pub(crate) fn backing_fingerprint(&self) -> Vec<(usize, usize)> {
        let mut output = Vec::new();
        self.generations.fingerprint(&mut output);
        self.terminal.fingerprint(&mut output);
        self.work.fingerprint(&mut output);
        output.sort_unstable();
        output
    }

    /// Accept a previously authenticated complete symbol, with atomic rejection.
    ///
    /// No failure changes rank/history/reservations/time. Exact duplicate success
    /// updates observed time only. Expired state is removed only by explicit expire.
    pub fn accept(
        &mut self,
        authenticated_packet: &[u8],
        now_ticks: u64,
    ) -> Result<AcceptStatus, Error> {
        self.check_time(now_ticks)?;
        let view = inspect(authenticated_packet, self.context, self.config.block)?;
        self.accept_validated_view(view, now_ticks, &mut |_| {})
    }

    /// Accept a typed symbol after the caller validates the selected outer context,
    /// integrity and replay policy. All dimensions and state constraints remain checked.
    pub fn accept_view(
        &mut self,
        view: crate::SymbolView<'_>,
        now_ticks: u64,
    ) -> Result<AcceptStatus, Error> {
        self.accept_view_observed(view, now_ticks, |_| {})
    }

    /// The same atomic acceptance transaction, with a scalar callback only at an
    /// actual capacity refusal. The callback cannot change admission or its error.
    pub fn accept_view_observed(
        &mut self,
        view: crate::SymbolView<'_>,
        now_ticks: u64,
        mut refused: impl FnMut(DecoderCapacity),
    ) -> Result<AcceptStatus, Error> {
        self.check_time(now_ticks)?;
        view.validate(self.config.block)?;
        self.accept_validated_view(view, now_ticks, &mut refused)
    }

    /// Accept the explicitly selected compact systematic extent. The existing
    /// reserved transaction rows restore only the validated algebraic zero tail;
    /// repair rows remain full width. All rejection and deadline ordering is the
    /// same as the regular typed API, which still requires full-width symbols.
    pub fn accept_compact_view_observed(
        &mut self,
        view: crate::SymbolView<'_>,
        now_ticks: u64,
        mut refused: impl FnMut(DecoderCapacity),
    ) -> Result<AcceptStatus, Error> {
        self.check_time(now_ticks)?;
        view.validate_compact_extent(self.config.block)?;
        self.accept_validated_view(view, now_ticks, &mut refused)
    }

    fn accept_validated_view(
        &mut self,
        view: crate::SymbolView<'_>,
        now_ticks: u64,
        refused: &mut impl FnMut(DecoderCapacity),
    ) -> Result<AcceptStatus, Error> {
        self.check_generation(view.generation)?;
        let mut new_generation = None;
        let generation = if let Some(generation) = self.generations.get(&view.generation) {
            if now_ticks >= generation.deadline {
                return Err(Error::Expired);
            }
            if generation.count != view.source_count || generation.width != view.coded_bytes {
                return Err(Error::Conflict);
            }
            if let Some(previous) = generation.received.get(&view.symbol) {
                if previous.coefficients != view.coefficients
                    || previous.payload.len() != view.coded_bytes
                    || previous.payload.get(..view.payload.len()) != Some(view.payload)
                    || previous
                        .payload
                        .get(view.payload.len()..)
                        .is_none_or(|tail| tail.iter().any(|byte| *byte != 0))
                {
                    return Err(Error::Conflict);
                }
                let progress = generation.progress(view.generation);
                self.last_now = now_ticks;
                return Ok(AcceptStatus::Duplicate(progress));
            }
            if generation.rank == generation.count {
                return Err(Error::CompletePending);
            }
            if generation.received.len() >= self.config.max_symbols_per_generation {
                refused(DecoderCapacity::SymbolSlots);
                return Err(Error::Capacity);
            }
            generation
        } else {
            if self.generations.len() >= self.config.max_generations {
                refused(DecoderCapacity::GenerationSlots);
                return Err(Error::Capacity);
            }
            let reservation = self
                .config
                .reservation(view.source_count, view.coded_bytes)?;
            if self
                .reserved
                .checked_add(reservation)
                .ok_or(Error::Arithmetic)?
                > self.config.max_reserved_bytes
            {
                refused(DecoderCapacity::LogicalReservation);
                return Err(Error::Capacity);
            }
            let deadline = now_ticks
                .checked_add(self.config.max_lifetime_ticks)
                .ok_or(Error::DeadlineOverflow)?;
            // Work rejection precedes any packet-sized allocation.
            self.config
                .block
                .work(view.source_count, view.coded_bytes)?;
            if self.generations.vacant().is_none() {
                new_generation = Some(Generation {
                    count: view.source_count,
                    width: view.coded_bytes,
                    deadline,
                    reservation,
                    basis: Basis::Legacy(vec![None; view.source_count]),
                    received: History::Legacy(BTreeMap::new()),
                    rank: 0,
                });
            }
            new_generation
                .as_ref()
                .or_else(|| self.generations.vacant())
                .ok_or(Error::Arithmetic)?
        };
        self.config
            .block
            .work(view.source_count, view.coded_bytes)?;
        let received_symbols = generation.received.len() + 1;
        let prepared = self.work.prepare(generation, view)?;
        let progress = Progress {
            generation: view.generation,
            rank: prepared.rank,
            required_rank: view.source_count,
            received_symbols,
        };
        let status = if prepared.rank == view.source_count {
            AcceptStatus::Complete(progress)
        } else if prepared.innovative {
            AcceptStatus::Innovative(progress)
        } else {
            AcceptStatus::Dependent(progress)
        };
        if let Some(generation) = self.generations.get_mut(&view.generation) {
            self.work.commit(generation, view.symbol, prepared)?;
        } else {
            let reservation = self
                .config
                .reservation(view.source_count, view.coded_bytes)?;
            let deadline = now_ticks
                .checked_add(self.config.max_lifetime_ticks)
                .ok_or(Error::DeadlineOverflow)?;
            let generation = self.generations.publish(view.generation, new_generation)?;
            generation.count = view.source_count;
            generation.width = view.coded_bytes;
            generation.deadline = deadline;
            generation.reservation = reservation;
            self.work.commit(generation, view.symbol, prepared)?;
            self.reserved += reservation;
        }
        self.highest = Some(
            self.highest
                .map_or(view.generation, |highest| highest.max(view.generation)),
        );
        self.prune_terminal();
        self.last_now = now_ticks;
        Ok(status)
    }

    /// Copy complete source payloads and retire the generation exactly once.
    ///
    /// The caller should expire at its current tick before retrieval. This method
    /// rejects deadlines already reached at the last observed successful tick.
    pub fn take_decoded(&mut self, generation: GenerationId) -> Result<DecodedBlock, Error> {
        self.check_generation(generation)?;
        let state = self
            .generations
            .get(&generation)
            .ok_or(Error::UnknownGeneration)?;
        if self.last_now >= state.deadline {
            return Err(Error::Expired);
        }
        if state.rank != state.count {
            return Err(Error::InsufficientRank);
        }
        let sources = self
            .decoded_sources(generation)?
            .map(<[u8]>::to_vec)
            .collect();
        self.commit_decoded(generation)?;
        Ok(DecodedBlock {
            generation,
            sources,
        })
    }

    /// Borrow complete original sources without allocating an owned output.
    pub fn decoded_sources(&self, generation: GenerationId) -> Result<DecodedSources<'_>, Error> {
        self.check_generation(generation)?;
        let state = self
            .generations
            .get(&generation)
            .ok_or(Error::UnknownGeneration)?;
        if self.last_now >= state.deadline {
            return Err(Error::Expired);
        }
        if state.rank != state.count {
            return Err(Error::InsufficientRank);
        }
        for index in 0..state.count {
            original_length(&state.basis.get(index).ok_or(Error::Arithmetic)?.payload)?;
        }
        Ok(DecodedSources { state, next: 0 })
    }
    /// Retire a validated complete generation after caller-owned copies succeed.
    pub fn commit_decoded(&mut self, generation: GenerationId) -> Result<(), Error> {
        self.decoded_sources(generation)?;
        let state = self
            .generations
            .get(&generation)
            .ok_or(Error::UnknownGeneration)?;
        let remaining = self
            .reserved
            .checked_sub(state.reservation)
            .ok_or(Error::Arithmetic)?;
        self.terminal.insert(generation, Terminal::Delivered)?;
        self.generations.remove(&generation);
        self.reserved = remaining;
        Ok(())
    }
    /// Explicit owned-output convenience; selected reserved consumers use expire_into.
    pub fn expire(&mut self, now_ticks: u64) -> Result<Vec<ExpiredGeneration>, Error> {
        self.check_time(now_ticks)?;
        let due = self
            .generations
            .iter()
            .filter(|(_, state)| now_ticks >= state.deadline)
            .count();
        let mut result = vec![
            ExpiredGeneration {
                generation: GenerationId(0),
                rank: 0,
                required_rank: 0
            };
            due
        ];
        let count = self.expire_into(now_ticks, &mut result)?;
        result.truncate(count);
        Ok(result)
    }
    /// Expire into caller-owned storage; short output leaves all state unchanged.
    pub fn expire_into(
        &mut self,
        now_ticks: u64,
        output: &mut [ExpiredGeneration],
    ) -> Result<usize, Error> {
        self.check_time(now_ticks)?;
        let count = self
            .generations
            .iter()
            .filter(|(_, state)| now_ticks >= state.deadline)
            .count();
        if output.len() < count {
            return Err(Error::OutputTooSmall { required: count });
        }
        let release = self
            .generations
            .iter()
            .filter(|(_, state)| now_ticks >= state.deadline)
            .try_fold(0usize, |sum, (_, state)| {
                sum.checked_add(state.reservation).ok_or(Error::Arithmetic)
            })?;
        let remaining = self
            .reserved
            .checked_sub(release)
            .ok_or(Error::Arithmetic)?;
        for (target, (&generation, state)) in output.iter_mut().zip(
            self.generations
                .iter()
                .filter(|(_, state)| now_ticks >= state.deadline),
        ) {
            *target = ExpiredGeneration {
                generation,
                rank: state.rank,
                required_rank: state.count,
            };
        }
        output[..count].sort_unstable_by_key(|entry| entry.generation);
        for entry in &output[..count] {
            self.terminal.insert(entry.generation, Terminal::Expired)?;
            self.generations.remove(&entry.generation);
        }
        self.reserved = remaining;
        self.last_now = now_ticks;
        self.prune_terminal();
        Ok(count)
    }

    /// Actual metadata-only buffer observation. This neither expires nor retrieves state.
    pub fn buffer_snapshot(&self) -> DecoderBuffers {
        let mut result = DecoderBuffers {
            generations: self.generations.len(),
            generations_capacity: self.config.max_generations,
            logical_reservation_bytes: self.reserved,
            logical_reservation_capacity: self.config.max_reserved_bytes,
            allocated_capacity_bytes: self.usage.map(|v| v.capacity_bytes),
            basis_rows_capacity: self.config.max_generations * self.config.block.max_sources,
            history_symbols_capacity: self.config.max_generations
                * self.config.max_symbols_per_generation,
            ..DecoderBuffers::default()
        };
        // All products/sums are bounded by the validated hard dimensional maxima.
        for (_, generation) in self.generations.iter() {
            result.basis_rows += generation.rank;
            result.history_symbols += generation.received.len();
            result.completed_generations += usize::from(generation.rank == generation.count);
        }
        result
    }

    /// Current rank/count for a live generation, including undelivered completion.
    pub fn progress(&self, generation: GenerationId) -> Option<Progress> {
        self.generations
            .get(&generation)
            .map(|state| state.progress(generation))
    }

    /// Conservative logical byte reservation, excluding allocator/container metadata.
    pub fn reserved_bytes(&self) -> usize {
        self.reserved
    }
    /// Live generation count, including full-rank blocks awaiting retrieval.
    pub fn generation_count(&self) -> usize {
        self.generations.len()
    }
    /// Bounded completed/expired tombstone count.
    pub fn terminal_count(&self) -> usize {
        self.terminal.len()
    }

    fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::TimeBackwards);
        }
        Ok(())
    }

    fn floor(&self, highest: GenerationId) -> u64 {
        highest.0.saturating_sub(self.config.generation_window - 1)
    }

    fn check_generation(&self, generation: GenerationId) -> Result<(), Error> {
        if let Some(highest) = self.highest {
            if generation.0 < self.floor(highest) {
                return Err(Error::StaleGeneration);
            }
            if generation > highest
                && self
                    .generations
                    .iter()
                    .any(|(live, _)| live.0 < self.floor(generation))
            {
                return Err(Error::WindowBlocked);
            }
        }
        match self.terminal.get(&generation) {
            Some(Terminal::Delivered) => Err(Error::AlreadyCompleted),
            Some(Terminal::Expired) => Err(Error::Expired),
            None => Ok(()),
        }
    }

    fn prune_terminal(&mut self) {
        if let Some(highest) = self.highest {
            let floor = self.floor(highest);
            self.terminal.retain_floor(floor);
        }
    }
}

/// Validated complete originals borrowed from one live decoder generation.
pub struct DecodedSources<'a> {
    state: &'a Generation,
    next: usize,
}
impl<'a> Iterator for DecodedSources<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.state.count {
            return None;
        }
        let row = self.state.basis.get(self.next)?;
        self.next += 1;
        let length = original_length(&row.payload).ok()?;
        row.payload.get(2..length + 2)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.state.count - self.next;
        (n, Some(n))
    }
}
impl ExactSizeIterator for DecodedSources<'_> {}

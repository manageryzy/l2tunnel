use crate::{
    BlockConfig, Error, FecContext, GenerationId, SymbolId, SymbolView, field, inspect,
    original_length,
};
use std::collections::BTreeMap;

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
    fn validate(self) -> Result<(), Error> {
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
    fn from_view(view: SymbolView<'_>) -> Self {
        Self {
            coefficients: view.coefficients.to_vec(),
            payload: view.payload.to_vec(),
        }
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
    basis: Vec<Option<Row>>,
    received: BTreeMap<SymbolId, Row>,
    rank: usize,
}

struct Prepared {
    basis: Vec<Option<Row>>,
    row: Row,
    innovative: bool,
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

    fn prepare(&self, view: SymbolView<'_>) -> Result<Prepared, Error> {
        let received = Row::from_view(view);
        let mut row = received.clone();
        let mut basis = self.basis.clone();
        for (pivot, existing) in basis.iter().enumerate() {
            if let Some(existing) = existing {
                let factor = *row.coefficients.get(pivot).ok_or(Error::Arithmetic)?;
                if factor != 0 {
                    row.eliminate(existing, factor);
                }
            }
        }
        let Some(pivot) = row
            .coefficients
            .iter()
            .position(|&coefficient| coefficient != 0)
        else {
            if row.payload.iter().any(|&byte| byte != 0) {
                return Err(Error::Conflict);
            }
            return Ok(Prepared {
                basis,
                row: received,
                innovative: false,
                rank: self.rank,
            });
        };
        row.normalize(pivot)?;
        row.validate_identifiable()?;
        for existing in basis.iter_mut().flatten() {
            let factor = *existing.coefficients.get(pivot).ok_or(Error::Arithmetic)?;
            if factor != 0 {
                existing.eliminate(&row, factor);
            }
            existing.validate_identifiable()?;
        }
        *basis.get_mut(pivot).ok_or(Error::Arithmetic)? = Some(row);
        let rank = self.rank.checked_add(1).ok_or(Error::Arithmetic)?;
        if rank == self.count {
            // Every final row must be a canonical identity row, including all
            // original length bytes and required zero extension.
            let mut maximum_length = 0;
            for (index, recovered) in basis.iter().enumerate() {
                let recovered = recovered.as_ref().ok_or(Error::Arithmetic)?;
                if recovered
                    .coefficients
                    .iter()
                    .enumerate()
                    .any(|(column, &coefficient)| coefficient != u8::from(column == index))
                {
                    return Err(Error::Arithmetic);
                }
                maximum_length = maximum_length.max(original_length(&recovered.payload)?);
            }
            if maximum_length.checked_add(2).ok_or(Error::Arithmetic)? != self.width {
                return Err(Error::InvalidSource);
            }
        }
        Ok(Prepared {
            basis,
            row: received,
            innovative: true,
            rank,
        })
    }

    fn commit(&mut self, symbol: SymbolId, prepared: Prepared) {
        self.basis = prepared.basis;
        self.rank = prepared.rank;
        self.received.insert(symbol, prepared.row);
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
    generations: BTreeMap<GenerationId, Generation>,
    terminal: BTreeMap<GenerationId, Terminal>,
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
            generations: BTreeMap::new(),
            terminal: BTreeMap::new(),
            highest: None,
            reserved: 0,
            last_now: 0,
        })
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
                if previous.coefficients != view.coefficients || previous.payload != view.payload {
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
                return Err(Error::Capacity);
            }
            generation
        } else {
            if self.generations.len() >= self.config.max_generations {
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
                return Err(Error::Capacity);
            }
            let deadline = now_ticks
                .checked_add(self.config.max_lifetime_ticks)
                .ok_or(Error::DeadlineOverflow)?;
            // Work rejection precedes any packet-sized allocation.
            self.config
                .block
                .work(view.source_count, view.coded_bytes)?;
            new_generation = Some(Generation {
                count: view.source_count,
                width: view.coded_bytes,
                deadline,
                reservation,
                basis: vec![None; view.source_count],
                received: BTreeMap::new(),
                rank: 0,
            });
            new_generation.as_ref().ok_or(Error::Arithmetic)?
        };
        self.config
            .block
            .work(view.source_count, view.coded_bytes)?;
        let prepared = generation.prepare(view)?;
        let progress = Progress {
            generation: view.generation,
            rank: prepared.rank,
            required_rank: view.source_count,
            received_symbols: generation.received.len() + 1,
        };
        let status = if prepared.rank == view.source_count {
            AcceptStatus::Complete(progress)
        } else if prepared.innovative {
            AcceptStatus::Innovative(progress)
        } else {
            AcceptStatus::Dependent(progress)
        };
        if let Some(mut generation) = new_generation {
            generation.commit(view.symbol, prepared);
            self.reserved += generation.reservation;
            self.generations.insert(view.generation, generation);
        } else if let Some(generation) = self.generations.get_mut(&view.generation) {
            generation.commit(view.symbol, prepared);
        } else {
            return Err(Error::Arithmetic);
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
        let mut sources = Vec::with_capacity(state.count);
        for row in &state.basis {
            let row = row.as_ref().ok_or(Error::Arithmetic)?;
            let length = original_length(&row.payload)?;
            sources.push(
                row.payload
                    .get(2..length + 2)
                    .ok_or(Error::Arithmetic)?
                    .to_vec(),
            );
        }
        let reservation = state.reservation;
        let remaining = self
            .reserved
            .checked_sub(reservation)
            .ok_or(Error::Arithmetic)?;
        self.generations.remove(&generation);
        self.reserved = remaining;
        self.terminal.insert(generation, Terminal::Delivered);
        Ok(DecodedBlock {
            generation,
            sources,
        })
    }

    /// Explicitly expire every due generation and retain bounded terminal IDs.
    pub fn expire(&mut self, now_ticks: u64) -> Result<Vec<ExpiredGeneration>, Error> {
        self.check_time(now_ticks)?;
        let expired: Vec<_> = self
            .generations
            .iter()
            .filter(|(_, state)| now_ticks >= state.deadline)
            .map(|(&generation, state)| ExpiredGeneration {
                generation,
                rank: state.rank,
                required_rank: state.count,
            })
            .collect();
        let release = self
            .generations
            .values()
            .filter(|state| now_ticks >= state.deadline)
            .try_fold(0_usize, |sum, state| {
                sum.checked_add(state.reservation).ok_or(Error::Arithmetic)
            })?;
        let remaining = self
            .reserved
            .checked_sub(release)
            .ok_or(Error::Arithmetic)?;
        for entry in &expired {
            self.generations.remove(&entry.generation);
            self.terminal.insert(entry.generation, Terminal::Expired);
        }
        self.reserved = remaining;
        self.last_now = now_ticks;
        self.prune_terminal();
        Ok(expired)
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
                    .keys()
                    .any(|live| live.0 < self.floor(generation))
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
            self.terminal.retain(|generation, _| generation.0 >= floor);
        }
    }
}

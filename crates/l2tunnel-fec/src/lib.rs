//! Bounded systematic block FEC over actual payload bytes in GF(256).
//!
//! Authenticate enclosing records before decoding. This crate supplies no
//! authentication, socket, real clock or complete transport mode.
use std::fmt;

mod decoder;
pub mod field;
pub mod legacy_sliding;
pub mod mixed_datagram;
pub mod path_shards;
pub mod research;
pub mod rolling;
pub mod storage;
pub mod striped;
pub mod striped_group;
mod symbol_output;
mod wire;

pub use decoder::{
    AcceptStatus, DecodedBlock, DecodedSources, Decoder, DecoderBuffers, DecoderCapacity,
    DecoderConfig, ExpiredGeneration, Progress,
};
pub use field::{cauchy_coefficients, compact_coefficients};
pub use wire::{HEADER_BYTES, SymbolKind, SymbolView, inspect};

/// Hard source-count ceiling for one sealed generation.
pub const MAX_SOURCES: usize = 256;
/// Hard original-source byte ceiling; larger records must be fragmented first.
pub const MAX_SOURCE_BYTES: usize = 4096;
/// Hard GF byte-operation budget per input, exclusive of bounded copies/parsing.
pub const MAX_WORK_PER_SYMBOL: u64 = 16_777_216;

/// Authenticated session identity; this value is not a secret or authenticator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionId(pub [u8; 16]);
/// Negotiated configuration epoch, with no local implicit reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch(pub u64);
/// Coding stream/channel identity within a session and epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelId(pub u32);
/// Nonrepeating generation ID scoped to a complete FecContext.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct GenerationId(pub u64);
/// Source index within a sealed generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceId(pub u16);
/// Systematic source index or unique nonwrapping repair identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SymbolId(pub u32);

/// Global direction; independent of which endpoint is constructing the object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client sends and server receives.
    ClientToServer,
    /// Server sends and client receives.
    ServerToClient,
}

impl Direction {
    fn wire(self) -> u8 {
        match self {
            Self::ClientToServer => 1,
            Self::ServerToClient => 2,
        }
    }
}

/// Previously authenticated coding-domain context checked in every packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FecContext {
    /// Authenticated session.
    pub session: SessionId,
    /// Negotiated epoch.
    pub epoch: Epoch,
    /// Coding channel.
    pub channel: ChannelId,
    /// Global sending direction.
    pub direction: Direction,
}

/// Local dimensional, wire and arithmetic-work limits shared by both endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockConfig {
    /// Maximum sources in a generation, 1..256.
    pub max_sources: usize,
    /// Maximum bytes in one original source, 1..4096.
    pub max_source_bytes: usize,
    /// FEC packet budget after subtracting all external framing/authentication.
    pub max_packet_bytes: usize,
    /// Conservative per-input field-operation allowance, at most 16,777,216.
    pub max_work_per_symbol: u64,
}

impl BlockConfig {
    fn validate(self) -> Result<(), Error> {
        if !(1..=MAX_SOURCES).contains(&self.max_sources)
            || !(1..=MAX_SOURCE_BYTES).contains(&self.max_source_bytes)
            || !(HEADER_BYTES + 4..=65_507).contains(&self.max_packet_bytes)
            || !(1..=MAX_WORK_PER_SYMBOL).contains(&self.max_work_per_symbol)
        {
            return Err(Error::InvalidConfig);
        }
        Ok(())
    }

    fn dimensions(self, sources: usize, width: usize) -> Result<(), Error> {
        if sources == 0
            || sources > self.max_sources
            || width < 3
            || width > self.max_source_bytes + 2
        {
            return Err(Error::InvalidDimensions);
        }
        let bytes = HEADER_BYTES
            .checked_add(sources)
            .and_then(|n| n.checked_add(width))
            .ok_or(Error::Arithmetic)?;
        if bytes > self.max_packet_bytes {
            return Err(Error::PacketTooLarge);
        }
        Ok(())
    }

    fn work(self, sources: usize, width: usize) -> Result<u64, Error> {
        let row = sources.checked_add(width).ok_or(Error::Arithmetic)?;
        let operations = sources
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(row))
            .and_then(|n| n.checked_add(16))
            .ok_or(Error::Arithmetic)?;
        let operations = u64::try_from(operations).map_err(|_| Error::Arithmetic)?;
        if operations > self.max_work_per_symbol {
            return Err(Error::WorkLimit);
        }
        Ok(operations)
    }
}

/// Explicit failure without a panic on peer packet bytes or local configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// A reusable encoder has no sealed generation yet.
    Unsealed,
    /// Caller output cannot hold the exact encoded result.
    OutputTooSmall {
        /// Required caller capacity.
        required: usize,
    },
    /// Invalid local dimension/count/memory/work/time configuration.
    InvalidConfig,
    /// Source count, vector width or original source length is outside local caps.
    InvalidDimensions,
    /// Empty, all-zero or noncanonical coefficient vector.
    InvalidCoefficients,
    /// Packet exceeds the configured FEC wire budget.
    PacketTooLarge,
    /// Magic, version, reserved bytes or exact encoded length is invalid.
    Malformed,
    /// Session, epoch, channel or direction mismatches the authenticated context.
    ContextMismatch,
    /// Same identity/descriptor differs, or equations disagree on payload bytes.
    Conflict,
    /// Recovered original length or required zero padding is invalid.
    InvalidSource,
    /// The conservative per-input arithmetic allowance is exceeded.
    WorkLimit,
    /// Live generation, received-symbol or reserved-byte capacity is exhausted.
    Capacity,
    /// Injected time moved backwards.
    TimeBackwards,
    /// Injected lifetime would overflow the tick domain.
    DeadlineOverflow,
    /// Generation deadline was reached; explicitly expire to reclaim live state.
    Expired,
    /// Generation was already delivered exactly once.
    AlreadyCompleted,
    /// Generation has full rank and is waiting for take_decoded.
    CompletePending,
    /// Generation ID is below the retained acceptance window.
    StaleGeneration,
    /// Advancing the generation window would evict live data.
    WindowBlocked,
    /// Requested generation has not been admitted.
    UnknownGeneration,
    /// A present generation has fewer independent equations than sources.
    InsufficientRank,
    /// Unique repair-symbol numbering cannot continue without a new generation.
    SymbolExhausted,
    /// Checked arithmetic or an internal checked invariant failed.
    Arithmetic,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "block FEC error: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Complete draft FEC packet; transport retries resend these exact bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedSymbol {
    /// Scoped generation identity.
    pub generation: GenerationId,
    /// Systematic or repair identity within this generation.
    pub symbol: SymbolId,
    /// Full header, explicit coefficients and actual coded payload bytes.
    pub bytes: Vec<u8>,
}

/// A sealed immutable source block, with unique repair-ID ownership.
pub struct BlockEncoder {
    context: FecContext,
    generation: GenerationId,
    config: BlockConfig,
    sources: Vec<Vec<u8>>,
    width: usize,
    next_repair: Option<SymbolId>,
    count: usize,
    sealed: bool,
    coefficients: Vec<u8>,
    repair_payload: Vec<u8>,
    usage: Option<storage::Usage>,
}

impl BlockEncoder {
    /// Copy, validate and seal a nonempty list of nonempty source payloads.
    pub fn new(
        context: FecContext,
        generation: GenerationId,
        config: BlockConfig,
        sources: &[&[u8]],
    ) -> Result<Self, Error> {
        config.validate()?;
        if sources.is_empty()
            || sources.len() > config.max_sources
            || sources
                .iter()
                .any(|source| source.is_empty() || source.len() > config.max_source_bytes)
        {
            return Err(Error::InvalidDimensions);
        }
        let maximum = sources
            .iter()
            .map(|source| source.len())
            .max()
            .ok_or(Error::InvalidDimensions)?;
        let width = maximum.checked_add(2).ok_or(Error::Arithmetic)?;
        config.dimensions(sources.len(), width)?;
        config.work(sources.len(), width)?;
        let mut padded = Vec::with_capacity(sources.len());
        for source in sources {
            let mut vector = vec![0; width];
            let length = u16::try_from(source.len()).map_err(|_| Error::InvalidDimensions)?;
            vector[..2].copy_from_slice(&length.to_be_bytes());
            vector[2..source.len() + 2].copy_from_slice(source);
            padded.push(vector);
        }
        let next_repair = Some(SymbolId(
            u32::try_from(sources.len()).map_err(|_| Error::Arithmetic)?,
        ));
        Ok(Self {
            context,
            generation,
            config,
            sources: padded,
            width,
            next_repair,
            count: sources.len(),
            sealed: true,
            coefficients: Vec::new(),
            repair_payload: Vec::new(),
            usage: None,
        })
    }

    /// Reserve reusable backing without inventing a sealed generation.
    pub fn new_reserved(
        context: FecContext,
        config: BlockConfig,
        limits: storage::Limits,
    ) -> Result<Self, storage::Error> {
        let plan = storage::EncoderPlan::for_encoder(config)?;
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let mut allocation = storage::Allocation::new(limits.capacity_bytes);
        Self::reserved_with(context, config, plan, &mut allocation)
    }
    pub(crate) fn reserved_with(
        context: FecContext,
        config: BlockConfig,
        plan: storage::EncoderPlan,
        a: &mut storage::Allocation,
    ) -> Result<Self, storage::Error> {
        let n = config.max_sources;
        let w = config.max_source_bytes + 2;
        let mut sources = a.vec(n)?;
        for _ in 0..n {
            sources.push(a.vec(w)?);
        }
        let mut coefficients = a.vec(n)?;
        coefficients.resize(n, 0);
        let mut repair_payload = a.vec(w)?;
        repair_payload.resize(w, 0);
        let usage = a.usage();
        if usage.capacity_bytes != plan.capacity_bytes() {
            return Err(storage::Error::Invariant);
        }
        Ok(Self {
            context,
            generation: GenerationId(0),
            config,
            sources,
            width: 0,
            next_repair: None,
            count: 0,
            sealed: false,
            coefficients,
            repair_payload,
            usage: Some(usage),
        })
    }
    /// Replace a reusable block only with a strictly newer generation identity.
    pub fn seal_sources<'a, I>(&mut self, generation: GenerationId, sources: I) -> Result<(), Error>
    where
        I: ExactSizeIterator<Item = &'a [u8]> + Clone,
    {
        self.config.validate()?;
        if self.sealed && generation <= self.generation {
            return Err(Error::StaleGeneration);
        }
        let count = sources.len();
        if count == 0 || count > self.config.max_sources {
            return Err(Error::InvalidDimensions);
        }
        // Capture stable borrows once, with a fixed bounded stack inventory. A
        // custom Clone iterator need not replay the same items on later passes.
        let mut borrowed = [None; MAX_SOURCES];
        let mut actual = 0usize;
        let mut maximum = 0usize;
        for source in sources {
            if actual >= count || source.is_empty() || source.len() > self.config.max_source_bytes {
                return Err(Error::InvalidDimensions);
            }
            borrowed[actual] = Some(source);
            actual += 1;
            maximum = maximum.max(source.len());
        }
        if actual != count {
            return Err(Error::InvalidDimensions);
        }
        let width = maximum.checked_add(2).ok_or(Error::Arithmetic)?;
        self.config.dimensions(count, width)?;
        self.config.work(count, width)?;
        if self.usage.is_some() {
            if self.sources.len() < count
                || self
                    .sources
                    .iter()
                    .take(count)
                    .any(|s| s.capacity() < width)
            {
                return Err(Error::Capacity);
            }
            for (target, source) in self
                .sources
                .iter_mut()
                .zip(borrowed[..count].iter().flatten())
            {
                target.clear();
                target.resize(width, 0);
                target[..2].copy_from_slice(&(source.len() as u16).to_be_bytes());
                target[2..2 + source.len()].copy_from_slice(source);
            }
        } else {
            let mut padded = Vec::with_capacity(count);
            for source in borrowed[..count].iter().flatten() {
                let mut v = vec![0; width];
                v[..2].copy_from_slice(&(source.len() as u16).to_be_bytes());
                v[2..2 + source.len()].copy_from_slice(source);
                padded.push(v);
            }
            self.sources = padded;
        }
        self.generation = generation;
        self.count = count;
        self.width = width;
        self.next_repair = Some(SymbolId(count as u32));
        self.sealed = true;
        Ok(())
    }
    /// Actual retained backing; legacy construction makes no reserved claim.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        self.usage
    }
    /// Encode a systematic record directly into caller-owned storage.
    pub fn systematic_into(&mut self, source: SourceId, output: &mut [u8]) -> Result<usize, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        let index = usize::from(source.0);
        if index >= self.count {
            return Err(Error::InvalidDimensions);
        }
        let required = HEADER_BYTES + self.count + self.width;
        if output.len() < required {
            return Err(Error::OutputTooSmall { required });
        }
        if self.usage.is_none() && self.coefficients.len() < self.count {
            self.coefficients.resize(self.count, 0);
        }
        self.coefficients[..self.count].fill(0);
        self.coefficients[index] = 1;
        wire::encode_into(
            self.context,
            self.generation,
            SymbolId(u32::from(source.0)),
            SymbolKind::Systematic,
            &self.coefficients[..self.count],
            &self.sources[index],
            output,
        )
    }
    /// Encode one repair directly into caller storage, consuming its ID once.
    pub fn repair_into(&mut self, coefficients: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        if coefficients.len() != self.count || coefficients.iter().all(|&c| c == 0) {
            return Err(Error::InvalidCoefficients);
        }
        self.config.work(self.count, self.width)?;
        let symbol = self.next_repair.ok_or(Error::SymbolExhausted)?;
        let required = HEADER_BYTES + self.count + self.width;
        if output.len() < required {
            return Err(Error::OutputTooSmall { required });
        }
        if self.usage.is_none() && self.repair_payload.len() < self.width {
            self.repair_payload.resize(self.width, 0);
        }
        repair_payload(
            coefficients,
            &self.sources[..self.count],
            &mut self.repair_payload[..self.width],
        );
        let bytes = wire::encode_into(
            self.context,
            self.generation,
            symbol,
            SymbolKind::Repair,
            coefficients,
            &self.repair_payload[..self.width],
            output,
        )?;
        self.next_repair = symbol.0.checked_add(1).map(SymbolId);
        Ok(bytes)
    }
    /// Existing Cauchy arithmetic using retained coefficient/output workspaces.
    pub fn cauchy_repair_into(
        &mut self,
        repair_index: u16,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        field::cauchy_column(self.count as u16, repair_index)?;
        self.config.work(self.count, self.width)?;
        let symbol = self.next_repair.ok_or(Error::SymbolExhausted)?;
        let required = HEADER_BYTES + self.count + self.width;
        if output.len() < required {
            return Err(Error::OutputTooSmall { required });
        }
        if self.usage.is_none() {
            self.coefficients.resize(self.count, 0);
            self.repair_payload.resize(self.width, 0);
        }
        field::cauchy_into(
            self.count as u16,
            repair_index,
            &mut self.coefficients[..self.count],
        )?;
        repair_payload(
            &self.coefficients[..self.count],
            &self.sources[..self.count],
            &mut self.repair_payload[..self.width],
        );
        let bytes = wire::encode_into(
            self.context,
            self.generation,
            symbol,
            SymbolKind::Repair,
            &self.coefficients[..self.count],
            &self.repair_payload[..self.width],
            output,
        )?;
        self.next_repair = symbol.0.checked_add(1).map(SymbolId);
        Ok(bytes)
    }

    /// Return one canonical systematic packet; repeated calls are byte-identical.
    pub fn systematic(&self, source: SourceId) -> Result<EncodedSymbol, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        let index = usize::from(source.0);
        let payload = self
            .sources
            .get(index)
            .filter(|_| index < self.count)
            .ok_or(Error::InvalidDimensions)?;
        let mut coefficients = vec![0; self.count];
        coefficients[index] = 1;
        wire::encode(
            self.context,
            self.generation,
            SymbolId(u32::from(source.0)),
            SymbolKind::Systematic,
            &coefficients,
            payload,
        )
    }

    /// Multiply actual source vectors by one explicit nonzero coefficient row.
    ///
    /// No randomness is hidden here: caller policy chooses coefficients. Every
    /// successful call consumes a fresh repair identity, even for dependent rows.
    pub fn repair(&mut self, coefficients: &[u8]) -> Result<EncodedSymbol, Error> {
        if !self.sealed {
            return Err(Error::Unsealed);
        }
        if coefficients.len() != self.count || coefficients.iter().all(|&value| value == 0) {
            return Err(Error::InvalidCoefficients);
        }
        self.config.work(self.count, self.width)?;
        let symbol = self.next_repair.ok_or(Error::SymbolExhausted)?;
        let mut payload = vec![0; self.width];
        repair_payload(coefficients, &self.sources[..self.count], &mut payload);
        let encoded = wire::encode(
            self.context,
            self.generation,
            symbol,
            SymbolKind::Repair,
            coefficients,
            &payload,
        )?;
        self.next_repair = symbol.0.checked_add(1).map(SymbolId);
        Ok(encoded)
    }

    /// Sealed source count.
    pub fn source_count(&self) -> usize {
        self.count
    }
    /// Coded vector bytes, including coded valid length and zero extension.
    pub fn coded_bytes(&self) -> usize {
        self.width
    }
}

fn repair_payload(coefficients: &[u8], sources: &[Vec<u8>], payload: &mut [u8]) {
    payload.fill(0);
    for (coefficient, source) in coefficients.iter().zip(sources) {
        for (out, byte) in payload.iter_mut().zip(source) {
            *out ^= field::multiply(*coefficient, *byte);
        }
    }
}

fn original_length(payload: &[u8]) -> Result<usize, Error> {
    let length_bytes: [u8; 2] = payload
        .get(..2)
        .ok_or(Error::InvalidSource)?
        .try_into()
        .map_err(|_| Error::InvalidSource)?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    let end = length.checked_add(2).ok_or(Error::Arithmetic)?;
    if length == 0
        || end > payload.len()
        || payload
            .get(end..)
            .ok_or(Error::InvalidSource)?
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(Error::InvalidSource);
    }
    Ok(length)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod storage_tests;

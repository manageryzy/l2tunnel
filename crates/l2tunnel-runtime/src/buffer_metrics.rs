//! Bounded, clock-injected backpressure observations for one runtime owner.
//!
//! Every runtime owner constructs one (always-on meter CSR,
//! `docs/modules/meter-csr.md`). The allocation is diagnostic memory, outside
//! protocol quotas; failure to construct or update it must not change protocol
//! behavior.
//!
//! Occupancy is a sample, not a blockage inference. Call `blocked` only after
//! actual eligible work is refused or a specifically identified operation waits.
//! Call `progress` only when that reason clears or makes observed progress. A
//! retained item or an idle read alone does not establish backpressure. Durations
//! include time until the runtime observes clearance, including scheduling delay.
//! Reasons and sites can overlap: only `owner().blocked` is their time union.
//! There are no clocks, payloads, event logs, per-event allocations, or I/O here.

use std::collections::TryReserveError;

pub(crate) mod csr;
mod observer;
mod pipeline_admission;
pub(crate) mod protocol_buffers;
mod udp_socket;
pub(crate) use observer::{Observer, SourceBoundary};

/// Stable bounded hook sites; unobserved sites are not evidence of zero pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Site {
    NativeIngress,
    NativeEgress,
    CodecAdmission,
    CodecDelivery,
    RecoverySend,
    RecoveryReceive,
    Management,
    CommonPrepared,
    CarrierSubmission,
    CarrierReceipt,
    CarrierInput,
    TlsWrite,
    TlsFlush,
    QuicSend,
    RawSend,
    RawCredit,
    ProxyAdmission,
    ProxyWriter,
    ProxyPhysicalReceipt,
    PipelineAdmission,
    NativeOutputQueue,
    NativeDeviceWrite,
    CommonUserSlot,
    RawControlSlot,
    DeferredFeedback,
    WireCredit,
    TlsSubmission,
    TlsInput,
    TlsReceipt,
    /// Session receiver credit, send side: in-flight data datagrams and bytes
    /// against the peer's granted window.
    CreditWindow,
}

impl Site {
    pub const ALL: [Self; 30] = [
        Self::NativeIngress,
        Self::NativeEgress,
        Self::CodecAdmission,
        Self::CodecDelivery,
        Self::RecoverySend,
        Self::RecoveryReceive,
        Self::Management,
        Self::CommonPrepared,
        Self::CarrierSubmission,
        Self::CarrierReceipt,
        Self::CarrierInput,
        Self::TlsWrite,
        Self::TlsFlush,
        Self::QuicSend,
        Self::RawSend,
        Self::RawCredit,
        Self::ProxyAdmission,
        Self::ProxyWriter,
        Self::ProxyPhysicalReceipt,
        Self::PipelineAdmission,
        Self::NativeOutputQueue,
        Self::NativeDeviceWrite,
        Self::CommonUserSlot,
        Self::RawControlSlot,
        Self::DeferredFeedback,
        Self::WireCredit,
        Self::TlsSubmission,
        Self::TlsInput,
        Self::TlsReceipt,
        Self::CreditWindow,
    ];
}

/// Carrier lane of an observation: shared by all lanes, or one authenticated
/// lane by index. Lanes beyond the second are no longer folded together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lane {
    Shared,
    Index(u16),
}

#[allow(non_upper_case_globals)]
impl Lane {
    /// Lane 0; kept so existing two-lane hooks read unchanged.
    pub const First: Self = Self::Index(0);
    /// Lane 1.
    pub const Second: Self = Self::Index(1);

    /// The lane at a runtime index; an index beyond u16 is clamped visibly
    /// to the last representable lane rather than folded into lane 1.
    pub fn at(index: usize) -> Self {
        Self::Index(u16::try_from(index).unwrap_or(u16::MAX))
    }

    /// Label in terminal `.bmetrics` reports: `Shared`, `First`, `Second`,
    /// then `Lane2`, `Lane3`, ... so existing report readers are unchanged.
    pub fn label(self) -> LaneLabel {
        LaneLabel(self)
    }

    /// Meter CSR segment: `shared` or `laneN`.
    pub fn segment(self) -> LaneSegment {
        LaneSegment(self)
    }
}

/// Display adapter for [`Lane::label`].
pub struct LaneLabel(Lane);
impl std::fmt::Display for LaneLabel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Lane::Shared => formatter.write_str("Shared"),
            Lane::Index(0) => formatter.write_str("First"),
            Lane::Index(1) => formatter.write_str("Second"),
            Lane::Index(index) => write!(formatter, "Lane{index}"),
        }
    }
}

/// Display adapter for [`Lane::segment`].
pub struct LaneSegment(Lane);
impl std::fmt::Display for LaneSegment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Lane::Shared => formatter.write_str("shared"),
            Lane::Index(index) => write!(formatter, "lane{index}"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Class {
    Shared,
    User,
    Feedback,
    Management,
}

impl Class {
    pub const ALL: [Self; 4] = [Self::Shared, Self::User, Self::Feedback, Self::Management];
}

/// A hook must select the actual cause, not infer it from queue occupancy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Reason {
    QueueFull,
    ByteCapacity,
    PeerCredit,
    IoPending,
    FlushPending,
    PhysicalReceiptPending,
    ConsumerPending,
    PolicyPacing,
    WorkBudget,
    BufferCapacity,
    NativeCredit,
    CodecStage,
    RecoveryWindow,
    SocketWrite,
    CarrierAdmission,
    ReceiptWait,
    PolicyCredit,
    Dependency,
    /// Actual CompactARQ transmission-history slot refusal.
    RecoveryHistoryCapacity,
}

impl Reason {
    pub const ALL: [Self; 19] = [
        Self::QueueFull,
        Self::ByteCapacity,
        Self::PeerCredit,
        Self::IoPending,
        Self::FlushPending,
        Self::PhysicalReceiptPending,
        Self::ConsumerPending,
        Self::PolicyPacing,
        Self::WorkBudget,
        Self::BufferCapacity,
        Self::NativeCredit,
        Self::CodecStage,
        Self::RecoveryWindow,
        Self::SocketWrite,
        Self::CarrierAdmission,
        Self::ReceiptWait,
        Self::PolicyCredit,
        Self::Dependency,
        Self::RecoveryHistoryCapacity,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key {
    pub site: Site,
    pub lane: Lane,
    pub class: Class,
}

/// Default key slots reserved per owner (decision 16 in
/// `docs/modules/meter-csr.md`); owners with more lanes reserve more.
pub const DEFAULT_SLOTS: usize = 64;

/// Unknown capacity must remain `None`; it is not an unbounded or empty queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    pub used: u64,
    pub capacity: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Occupancy {
    pub bytes: Option<Extent>,
    pub items: Option<Extent>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Invalid {
    pub clock_regression: bool,
    pub occupancy_exceeds_capacity: bool,
    pub update_after_finish: bool,
    pub counter_overflow: bool,
    /// A key found no free slot; its observations are counted, not kept.
    pub slots_exhausted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ClockRegression,
    OccupancyExceedsCapacity,
    Finished,
    /// Every reserved key slot is in use by other keys.
    SlotsExhausted,
}

/// Capacity and high-water values are samples, not continuous kernel telemetry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Gauge {
    pub samples: u64,
    pub latest: Option<Extent>,
    pub high_water: Option<u64>,
    pub minimum_known_capacity: Option<u64>,
    pub maximum_known_capacity: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurationSnapshot {
    pub episodes: u64,
    pub completed_episodes: u64,
    pub censored_episodes: u64,
    pub completed_us: u64,
    pub censored_us: u64,
    pub open_us: Option<u64>,
    /// Maximum observed duration, including the current open interval.
    pub maximum_us: u64,
    /// Completed (never censored) durations by log2 bucket.
    pub histogram: l2tunnel_meters::Histogram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReasonSnapshot {
    pub observed: bool,
    /// Calls returning the same refusal do not create additional episodes.
    pub refusals: u64,
    /// Refusals whose independent producer identity was not available. Their
    /// duration is unmeasured, not zero, and does not contribute to owner union.
    pub untimed_refusals: u64,
    /// Observed progress calls, including progress when no blockage was open.
    pub progress: u64,
    pub blocked: DurationSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeySnapshot {
    pub first_observed_us: Option<u64>,
    pub last_observed_us: Option<u64>,
    pub bytes: Gauge,
    pub items: Gauge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerSnapshot {
    pub first_observed_us: Option<u64>,
    pub last_observed_us: Option<u64>,
    /// Span from the first hook to this query/terminal boundary, not process age.
    pub observed_span_us: Option<u64>,
    pub finished_at_us: Option<u64>,
    pub active_reason_slots: usize,
    /// Union of observed blocked intervals; never the sum of site durations.
    pub blocked: DurationSnapshot,
    pub diagnostic_heap_bytes: usize,
    pub invalid: Invalid,
    /// Key slots in use and reserved.
    pub slots_used: usize,
    pub slot_capacity: usize,
    /// Hook calls whose key found no free slot.
    pub slots_exhausted: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Duration {
    since: Option<u64>,
    episodes: u64,
    completed_episodes: u64,
    censored_episodes: u64,
    completed_us: u64,
    censored_us: u64,
    maximum_us: u64,
    histogram: l2tunnel_meters::Histogram,
}

impl Duration {
    fn begin(&mut self, now: u64, invalid: &mut Invalid) {
        if self.since.is_none() {
            self.since = Some(now);
            add(&mut self.episodes, 1, invalid);
        }
    }

    fn end(&mut self, now: u64, censored: bool, invalid: &mut Invalid) {
        if let Some(since) = self.since.take() {
            // Every mutation was checked against the owner's monotonic watermark.
            let elapsed = now - since;
            self.maximum_us = self.maximum_us.max(elapsed);
            if censored {
                add(&mut self.censored_episodes, 1, invalid);
                add(&mut self.censored_us, elapsed, invalid);
            } else {
                add(&mut self.completed_episodes, 1, invalid);
                add(&mut self.completed_us, elapsed, invalid);
                if !self.histogram.record(elapsed) {
                    invalid.counter_overflow = true;
                }
            }
        }
    }

    fn snapshot(self, now: u64) -> DurationSnapshot {
        let open_us = self.since.map(|since| now - since);
        DurationSnapshot {
            episodes: self.episodes,
            completed_episodes: self.completed_episodes,
            censored_episodes: self.censored_episodes,
            completed_us: self.completed_us,
            censored_us: self.censored_us,
            open_us,
            maximum_us: self.maximum_us.max(open_us.unwrap_or(0)),
            histogram: self.histogram,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ReasonState {
    duration: Duration,
    refusals: u64,
    untimed_refusals: u64,
    progress: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Cell {
    first: Option<u64>,
    last: Option<u64>,
    bytes: Gauge,
    items: Gauge,
    reasons: [ReasonState; Reason::ALL.len()],
}

/// Exactly one bounded allocation on construction; updates and snapshots allocate
/// nothing. All hooks for this owner must use the same monotonic tick origin.
///
/// Keys occupy reserved slots in first-observation order. A key that finds no
/// free slot is counted in `slots_exhausted` and marks the owner invalid; it
/// never evicts or merges into another key.
pub struct Collector {
    slots: Vec<(Key, Cell)>,
    first: Option<u64>,
    last: Option<u64>,
    finished: Option<u64>,
    active: usize,
    union: Duration,
    invalid: Invalid,
    slots_exhausted: u64,
}

impl Collector {
    /// A collector with [`DEFAULT_SLOTS`] key slots.
    pub fn new() -> Result<Self, TryReserveError> {
        Self::with_slots(DEFAULT_SLOTS)
    }

    /// A collector with exactly `slots` key slots.
    pub fn with_slots(slots: usize) -> Result<Self, TryReserveError> {
        let mut storage = Vec::new();
        storage.try_reserve_exact(slots)?;
        Ok(Self {
            slots: storage,
            first: None,
            last: None,
            finished: None,
            active: 0,
            union: Duration::default(),
            invalid: Invalid::default(),
            slots_exhausted: 0,
        })
    }

    /// Actual retained allocation, independent of the observation clock.
    pub fn heap_bytes(&self) -> usize {
        // Vec allocation guarantees capacity * element size fits in isize.
        self.slots.capacity() * std::mem::size_of::<(Key, Cell)>()
    }

    /// Observed (key, reason) pairs; bounds the CSR wait blocks.
    pub fn observed_reasons(&self) -> usize {
        self.slots
            .iter()
            .map(|(_, cell)| {
                cell.reasons
                    .iter()
                    .filter(|state| state.refusals != 0 || state.progress != 0)
                    .count()
            })
            .sum()
    }

    /// Keys observed so far, in first-observation order.
    pub fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        self.slots.iter().map(|(key, _)| *key)
    }

    fn position(&self, key: Key) -> Option<usize> {
        self.slots.iter().position(|(slot, _)| *slot == key)
    }

    /// The cell of `key`, claiming a free slot on first use. Never allocates:
    /// the vector never grows beyond its reserved capacity.
    fn cell_mut(&mut self, key: Key) -> Result<&mut Cell, Error> {
        let index = match self.position(key) {
            Some(index) => index,
            None if self.slots.len() < self.slots.capacity() => {
                self.slots.push((key, Cell::default()));
                self.slots.len() - 1
            }
            None => {
                self.invalid.slots_exhausted = true;
                self.slots_exhausted = self.slots_exhausted.saturating_add(1);
                return Err(Error::SlotsExhausted);
            }
        };
        Ok(&mut self.slots[index].1)
    }

    fn cell(&self, key: Key) -> Cell {
        self.position(key)
            .map_or_else(Cell::default, |index| self.slots[index].1)
    }

    /// Samples actual retained usage. Does not begin or end a blocked interval.
    pub fn sample(&mut self, key: Key, now: u64, value: Occupancy) -> Result<(), Error> {
        self.check_update(now)?;
        if [value.bytes, value.items]
            .into_iter()
            .flatten()
            .any(|extent| {
                extent
                    .capacity
                    .is_some_and(|capacity| extent.used > capacity)
            })
        {
            self.invalid.occupancy_exceeds_capacity = true;
            return Err(Error::OccupancyExceedsCapacity);
        }
        self.observe(key, now)?;
        let mut invalid = self.invalid;
        let cell = self.cell_mut(key)?;
        sample(&mut cell.bytes, value.bytes, &mut invalid);
        sample(&mut cell.items, value.items, &mut invalid);
        self.invalid = invalid;
        Ok(())
    }

    pub fn blocked(&mut self, key: Key, reason: Reason, now: u64) -> Result<(), Error> {
        self.check_update(now)?;
        self.observe(key, now)?;
        let mut invalid = self.invalid;
        let state = &mut self.cell_mut(key)?.reasons[reason as usize];
        add(&mut state.refusals, 1, &mut invalid);
        let began = state.duration.since.is_none();
        if began {
            state.duration.begin(now, &mut invalid);
        }
        if began {
            if self.active == 0 {
                self.union.begin(now, &mut invalid);
            }
            // One active bit per fixed slot; the fixed catalog bounds this count.
            self.active += 1;
        }
        self.invalid = invalid;
        Ok(())
    }

    /// Count a real refusal when an interval cannot be keyed without conflating
    /// independent channels or epochs. This deliberately does not start a timer.
    pub fn refused(&mut self, key: Key, reason: Reason, now: u64) -> Result<(), Error> {
        self.check_update(now)?;
        self.observe(key, now)?;
        let mut invalid = self.invalid;
        let state = &mut self.cell_mut(key)?.reasons[reason as usize];
        add(&mut state.refusals, 1, &mut invalid);
        add(&mut state.untimed_refusals, 1, &mut invalid);
        self.invalid = invalid;
        Ok(())
    }

    /// The caller observes this specific cause clear. Other reasons remain open.
    pub fn progress(&mut self, key: Key, reason: Reason, now: u64) -> Result<(), Error> {
        self.check_update(now)?;
        self.observe(key, now)?;
        let mut invalid = self.invalid;
        let state = &mut self.cell_mut(key)?.reasons[reason as usize];
        add(&mut state.progress, 1, &mut invalid);
        let ended = state.duration.since.is_some();
        if ended {
            state.duration.end(now, false, &mut invalid);
            self.active -= 1;
            if self.active == 0 {
                self.union.end(now, false, &mut invalid);
            }
        }
        self.invalid = invalid;
        Ok(())
    }

    /// Censors unresolved intervals. This is not observed recovery. Repeating
    /// this exact terminal timestamp is idempotent; no duration grows afterward.
    pub fn finish(&mut self, now: u64) -> Result<(), Error> {
        if self.finished == Some(now) {
            return Ok(());
        }
        self.check_update(now)?;
        for (_, cell) in &mut self.slots {
            for state in &mut cell.reasons {
                state.duration.end(now, true, &mut self.invalid);
            }
        }
        self.union.end(now, true, &mut self.invalid);
        self.active = 0;
        self.finished = Some(now);
        Ok(())
    }

    /// Read-only query. Repeated snapshots never add duration to stored totals.
    pub fn owner(&self, now: u64) -> Result<OwnerSnapshot, Error> {
        let now = self.query_time(now)?;
        Ok(OwnerSnapshot {
            first_observed_us: self.first,
            last_observed_us: self.last,
            observed_span_us: self.first.map(|first| now - first),
            finished_at_us: self.finished,
            active_reason_slots: self.active,
            blocked: self.union.snapshot(now),
            diagnostic_heap_bytes: self.heap_bytes(),
            invalid: self.invalid,
            slots_used: self.slots.len(),
            slot_capacity: self.slots.capacity(),
            slots_exhausted: self.slots_exhausted,
        })
    }

    pub fn key(&self, key: Key) -> KeySnapshot {
        let cell = self.cell(key);
        KeySnapshot {
            first_observed_us: cell.first,
            last_observed_us: cell.last,
            bytes: cell.bytes,
            items: cell.items,
        }
    }

    pub fn reason(&self, key: Key, reason: Reason, now: u64) -> Result<ReasonSnapshot, Error> {
        let now = self.query_time(now)?;
        let state = self.cell(key).reasons[reason as usize];
        Ok(ReasonSnapshot {
            observed: state.refusals != 0 || state.progress != 0,
            refusals: state.refusals,
            progress: state.progress,
            untimed_refusals: state.untimed_refusals,
            blocked: state.duration.snapshot(now),
        })
    }

    fn check_update(&mut self, now: u64) -> Result<(), Error> {
        if self.finished.is_some() {
            self.invalid.update_after_finish = true;
            return Err(Error::Finished);
        }
        if self.last.is_some_and(|last| now < last) {
            self.invalid.clock_regression = true;
            return Err(Error::ClockRegression);
        }
        Ok(())
    }

    fn observe(&mut self, key: Key, now: u64) -> Result<(), Error> {
        let cell = self.cell_mut(key)?;
        cell.first.get_or_insert(now);
        cell.last = Some(now);
        self.first.get_or_insert(now);
        self.last = Some(now);
        Ok(())
    }

    fn query_time(&self, now: u64) -> Result<u64, Error> {
        if self.last.is_some_and(|last| now < last)
            || self.finished.is_some_and(|finished| now < finished)
        {
            return Err(Error::ClockRegression);
        }
        Ok(self.finished.unwrap_or(now))
    }
}

fn add(value: &mut u64, amount: u64, invalid: &mut Invalid) {
    match value.checked_add(amount) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            invalid.counter_overflow = true;
        }
    }
}

fn sample(gauge: &mut Gauge, value: Option<Extent>, invalid: &mut Invalid) {
    if let Some(value) = value {
        add(&mut gauge.samples, 1, invalid);
        gauge.latest = Some(value);
        gauge.high_water = Some(gauge.high_water.unwrap_or(0).max(value.used));
        if let Some(capacity) = value.capacity {
            gauge.minimum_known_capacity = Some(
                gauge
                    .minimum_known_capacity
                    .unwrap_or(capacity)
                    .min(capacity),
            );
            gauge.maximum_known_capacity = Some(
                gauge
                    .maximum_known_capacity
                    .unwrap_or(capacity)
                    .max(capacity),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Key = Key {
        site: Site::TlsWrite,
        lane: Lane::First,
        class: Class::User,
    };
    const B: Key = Key {
        site: Site::ProxyWriter,
        lane: Lane::Shared,
        class: Class::User,
    };

    #[test]
    fn full_occupancy_does_not_infer_backpressure_or_unknown_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        assert_eq!(
            collector.sample(
                A,
                10,
                Occupancy {
                    bytes: Some(Extent {
                        used: 64,
                        capacity: Some(64)
                    }),
                    items: Some(Extent {
                        used: 1,
                        capacity: None
                    }),
                }
            ),
            Ok(())
        );
        assert_eq!(collector.key(A).bytes.high_water, Some(64));
        assert_eq!(collector.key(A).items.minimum_known_capacity, None);
        assert_eq!(collector.key(B).first_observed_us, None);
        assert_eq!(collector.owner(30).map(|s| s.blocked.episodes), Ok(0));
        assert_eq!(
            collector
                .reason(A, Reason::QueueFull, 30)
                .map(|s| s.observed),
            Ok(false)
        );
        Ok(())
    }

    #[test]
    fn repeated_refusals_and_read_only_snapshots_keep_original_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        assert_eq!(collector.blocked(A, Reason::IoPending, 10), Ok(()));
        assert_eq!(collector.blocked(A, Reason::IoPending, 20), Ok(()));
        let before = collector.reason(A, Reason::IoPending, 25);
        assert_eq!(before, collector.reason(A, Reason::IoPending, 25));
        assert_eq!(
            before.map(|s| (s.refusals, s.blocked.episodes, s.blocked.open_us)),
            Ok((2, 1, Some(15)))
        );
        assert_eq!(collector.progress(A, Reason::IoPending, 30), Ok(()));
        assert_eq!(
            collector.reason(A, Reason::IoPending, 40).map(|s| (
                s.blocked.completed_us,
                s.blocked.completed_episodes,
                s.blocked.open_us
            )),
            Ok((20, 1, None))
        );
        Ok(())
    }

    #[test]
    fn overlapping_sites_and_reasons_use_owner_union_not_sum()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        assert_eq!(collector.blocked(A, Reason::IoPending, 10), Ok(()));
        assert_eq!(collector.blocked(B, Reason::QueueFull, 20), Ok(()));
        assert_eq!(collector.blocked(A, Reason::ByteCapacity, 25), Ok(()));
        assert_eq!(collector.progress(A, Reason::IoPending, 30), Ok(()));
        assert_eq!(collector.progress(B, Reason::QueueFull, 40), Ok(()));
        assert_eq!(
            collector
                .owner(45)
                .map(|s| (s.active_reason_slots, s.blocked.open_us)),
            Ok((1, Some(35)))
        );
        assert_eq!(collector.progress(A, Reason::ByteCapacity, 50), Ok(()));
        assert_eq!(
            collector
                .owner(50)
                .map(|s| (s.blocked.episodes, s.blocked.completed_us)),
            Ok((1, 40))
        );
        assert_eq!(
            collector
                .reason(A, Reason::IoPending, 50)
                .map(|s| s.blocked.completed_us),
            Ok(20)
        );
        assert_eq!(
            collector
                .reason(B, Reason::QueueFull, 50)
                .map(|s| s.blocked.completed_us),
            Ok(20)
        );
        assert_eq!(
            collector
                .reason(A, Reason::ByteCapacity, 50)
                .map(|s| s.blocked.completed_us),
            Ok(25)
        );
        Ok(())
    }

    #[test]
    fn terminal_censors_without_fake_recovery_or_post_terminal_growth()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        assert_eq!(collector.blocked(A, Reason::FlushPending, 10), Ok(()));
        assert_eq!(collector.finish(40), Ok(()));
        assert_eq!(collector.finish(40), Ok(()));
        assert_eq!(
            collector.reason(A, Reason::FlushPending, 90).map(|s| (
                s.progress,
                s.blocked.completed_episodes,
                s.blocked.censored_episodes,
                s.blocked.censored_us,
                s.blocked.open_us
            )),
            Ok((0, 0, 1, 30, None))
        );
        assert_eq!(
            collector
                .owner(90)
                .map(|s| (s.observed_span_us, s.blocked.censored_us)),
            Ok((Some(30), 30))
        );
        assert_eq!(
            collector.progress(A, Reason::FlushPending, 90),
            Err(Error::Finished)
        );
        assert_eq!(
            collector.owner(90).map(|s| s.invalid.update_after_finish),
            Ok(true)
        );
        Ok(())
    }

    #[test]
    fn bad_samples_and_clock_regression_are_explicit_and_do_not_rewrite_history()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        assert_eq!(collector.blocked(A, Reason::IoPending, 20), Ok(()));
        assert_eq!(
            collector.progress(A, Reason::IoPending, 19),
            Err(Error::ClockRegression)
        );
        assert_eq!(
            collector.sample(
                A,
                21,
                Occupancy {
                    bytes: Some(Extent {
                        used: 2,
                        capacity: Some(1)
                    }),
                    items: None
                }
            ),
            Err(Error::OccupancyExceedsCapacity)
        );
        assert_eq!(collector.key(A).bytes.latest, None);
        assert_eq!(
            collector.owner(21).map(|s| (
                s.invalid.clock_regression,
                s.invalid.occupancy_exceeds_capacity,
                s.blocked.open_us
            )),
            Ok((true, true, Some(1)))
        );
        assert_eq!(collector.progress(A, Reason::IoPending, 30), Ok(()));
        assert_eq!(collector.owner(30).map(|s| s.blocked.completed_us), Ok(10));
        Ok(())
    }

    #[test]
    fn counters_saturate_only_with_visible_overflow_and_fixed_storage()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        let capacity = collector.slots.capacity();
        collector
            .cell_mut(A)
            .map_err(|error| format!("{error:?}"))?
            .reasons[Reason::IoPending as usize]
            .refusals = u64::MAX;
        assert_eq!(collector.blocked(A, Reason::IoPending, 0), Ok(()));
        assert_eq!(collector.progress(A, Reason::IoPending, u64::MAX), Ok(()));
        assert_eq!(
            collector
                .owner(u64::MAX)
                .map(|s| (s.invalid.counter_overflow, s.blocked.completed_us)),
            Ok((true, u64::MAX))
        );
        assert_eq!(collector.slots.capacity(), capacity);
        assert_eq!(collector.slots.len(), 1);
        Ok(())
    }

    #[test]
    fn exhausted_slots_are_counted_never_merged_or_grown() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut collector = Collector::with_slots(2)?;
        let third = Key {
            site: Site::QuicSend,
            lane: Lane::at(2),
            class: Class::User,
        };
        assert_eq!(collector.blocked(A, Reason::IoPending, 1), Ok(()));
        assert_eq!(collector.blocked(B, Reason::QueueFull, 2), Ok(()));
        assert_eq!(
            collector.blocked(third, Reason::QueueFull, 3),
            Err(Error::SlotsExhausted)
        );
        assert_eq!(
            collector.sample(third, 4, Occupancy::default()),
            Err(Error::SlotsExhausted)
        );
        let owner = collector.owner(5).map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            (owner.slots_used, owner.slot_capacity, owner.slots_exhausted),
            (2, 2, 2)
        );
        assert!(owner.invalid.slots_exhausted);
        assert_eq!(collector.key(third).first_observed_us, None);
        assert_eq!(collector.keys().collect::<Vec<_>>(), vec![A, B]);
        assert_eq!(collector.slots.capacity(), 2);
        Ok(())
    }

    #[test]
    fn completed_waits_fill_histograms_and_lanes_stay_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut collector = Collector::new()?;
        let lane2 = Key {
            lane: Lane::at(2),
            ..A
        };
        let lane3 = Key {
            lane: Lane::at(3),
            ..A
        };
        assert_eq!(collector.blocked(lane2, Reason::IoPending, 0), Ok(()));
        assert_eq!(collector.progress(lane2, Reason::IoPending, 100), Ok(()));
        assert_eq!(collector.blocked(lane3, Reason::IoPending, 100), Ok(()));
        assert_eq!(collector.finish(200), Ok(()));
        let completed = collector
            .reason(lane2, Reason::IoPending, 200)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            completed.blocked.histogram.counts()[l2tunnel_meters::Histogram::bucket(100)],
            1
        );
        let censored = collector
            .reason(lane3, Reason::IoPending, 200)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(censored.blocked.censored_us, 100);
        assert_eq!(censored.blocked.histogram.counts().iter().sum::<u64>(), 0);
        assert_eq!(Lane::at(2).label().to_string(), "Lane2");
        assert_eq!(Lane::First.label().to_string(), "First");
        assert_eq!(Lane::Shared.segment().to_string(), "shared");
        assert_eq!(Lane::at(7).segment().to_string(), "lane7");
        Ok(())
    }
}

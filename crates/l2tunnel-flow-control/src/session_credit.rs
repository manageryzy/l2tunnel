//! Session receiver credit: a processed window plus a measured drain rate.
//!
//! The receiver of data datagrams grants the peer a limit in the peer's own
//! data packet numbers and a byte allowance above the highest packet it has
//! processed, and reports how fast it drains. The sender stays inside both and
//! paces data to the drain rate. Values are cumulative, so a lost [`Credit`] is
//! replaced by the next one; nothing here retransmits.
//!
//! Pure state: time is injected as a monotonic `Duration`, storage is
//! reserved at construction and peer input is authenticated by the caller.
//! Design: `docs/modules/receiver-credit.md`.

use std::collections::VecDeque;
use std::fmt;
use std::time::Duration;

/// Canonical encoded size of one [`Credit`].
pub const WIRE_BYTES: usize = 64;
/// Leading tag that distinguishes a Credit body from other control bodies.
pub const MAGIC: [u8; 4] = *b"L2CR";
const VERSION: u8 = 1;
/// Drain estimate bin width.
const BIN: Duration = Duration::from_millis(25);
/// Drain bins; the estimate uses the completed ones (175 ms).
const BINS: usize = 8;
/// Socket allowance bytes per granted datagram of allowance (upper clamp;
/// small-datagram streams scale down to [`MIN_ALLOWANCE_BYTES_PER_DATAGRAM`]).
const ALLOWANCE_BYTES_PER_DATAGRAM: u64 = 1024;
const MIN_ALLOWANCE_BYTES_PER_DATAGRAM: u64 = 256;
/// Minimum-RTT history: ten one-second bins.
const RTT_BIN: Duration = Duration::from_secs(1);
const RTT_BINS: usize = 10;
/// Pacing floor over the peer's drain rate, as a fraction.
const PACING_GAIN: (u64, u64) = (5, 4);
/// Pacing over the peer's drain rate before any RTT sample.
const PACING_GAIN_UNTIMED: u64 = 2;
/// Pacing burst in maximum data datagrams.
const PACING_BURST_DATAGRAMS: u64 = 16;
/// Configuration bounds.
const MAX_CEILING_DATAGRAMS: u64 = 65_536;
const MAX_CEILING_BYTES: u64 = 64 << 20;
const MIN_FLOOR_DATAGRAMS: u64 = 16;

/// Session credit failures. None is caused by ordinary packet loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Not a canonical Credit body.
    Malformed,
    /// Configuration outside the documented bounds.
    Configuration,
    /// Time moved backwards.
    Time,
    /// Arithmetic would overflow.
    Overflow,
    /// A sent data datagram is outside the granted window or out of order.
    Window,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed session credit",
            Self::Configuration => "invalid session credit configuration",
            Self::Time => "session credit time regression",
            Self::Overflow => "session credit arithmetic overflow",
            Self::Window => "data datagram outside the session credit window",
        })
    }
}
impl std::error::Error for Error {}

/// One credit grant from the receiver of data datagrams.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Credit {
    /// Strictly increasing per Credit sender, starting at 1.
    pub serial: u64,
    /// Highest processed data packet number plus one; zero before any.
    pub processed: u64,
    /// The peer may send data packet numbers below this value.
    pub limit: u64,
    /// Maximum data wire bytes the peer may have sent above `processed`.
    pub bytes_above: u64,
    /// Measured processed data wire bytes per second.
    pub drain_bytes: u64,
    /// Measured processed data datagrams per second.
    pub drain_datagrams: u64,
}
impl Credit {
    /// Encode canonically. Rejects values that [`Credit::decode`] would reject.
    pub fn encode(&self) -> Result<[u8; WIRE_BYTES], Error> {
        self.check()?;
        let mut out = [0; WIRE_BYTES];
        out[..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        for (index, value) in [
            self.serial,
            self.processed,
            self.limit,
            self.bytes_above,
            self.drain_bytes,
            self.drain_datagrams,
        ]
        .into_iter()
        .enumerate()
        {
            let start = 8 + 8 * index;
            out[start..start + 8].copy_from_slice(&value.to_be_bytes());
        }
        Ok(out)
    }
    /// Whether `bytes` carries the Credit tag; says nothing about validity.
    pub fn is_tagged(bytes: &[u8]) -> bool {
        bytes.get(..4) == Some(&MAGIC[..])
    }
    /// Decode one canonical Credit body.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; WIRE_BYTES] = bytes.try_into().map_err(|_| Error::Malformed)?;
        if bytes[..4] != MAGIC
            || bytes[4] != VERSION
            || bytes[5..8] != [0; 3]
            || bytes[56..] != [0; 8]
        {
            return Err(Error::Malformed);
        }
        let field = |index: usize| {
            let start = 8 + 8 * index;
            let mut value = [0; 8];
            value.copy_from_slice(&bytes[start..start + 8]);
            u64::from_be_bytes(value)
        };
        let credit = Self {
            serial: field(0),
            processed: field(1),
            limit: field(2),
            bytes_above: field(3),
            drain_bytes: field(4),
            drain_datagrams: field(5),
        };
        credit.check()?;
        Ok(credit)
    }
    fn check(&self) -> Result<(), Error> {
        if self.serial == 0 || self.limit < self.processed {
            return Err(Error::Malformed);
        }
        Ok(())
    }
}

/// Authenticated session credit configuration, identical on both peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Config {
    /// Initial and minimum datagram window.
    pub floor_datagrams: u64,
    /// Maximum datagram window and sender in-flight ring size.
    pub ceiling_datagrams: u64,
    /// Initial and minimum byte window.
    pub floor_bytes: u64,
    /// Maximum byte window.
    pub ceiling_bytes: u64,
    /// Credit repeat period while data flows.
    pub period: Duration,
    /// Heartbeat period without data.
    pub idle_period: Duration,
}
impl Config {
    /// Smallest record-receive range (`min(packets_per_key,
    /// max_forward_packets)`) this credit configuration accepts: four times the
    /// window ceiling, so the sender's half-range bound never binds inside a
    /// credit window.
    pub fn minimum_range(self) -> Result<u64, Error> {
        self.ceiling_datagrams.checked_mul(4).ok_or(Error::Overflow)
    }
    /// The configuration to run with a record-receive range of `range`: the
    /// datagram ceiling (and the floor, if above it) lowered to `range / 4`
    /// when `range` is below [`Config::minimum_range`], otherwise unchanged.
    /// A range below four minimum floors (64 datagrams) cannot hold a valid
    /// window and is refused.
    pub fn fit_range(self, range: u64) -> Result<Self, Error> {
        let ceiling = range / 4;
        if ceiling < MIN_FLOOR_DATAGRAMS {
            return Err(Error::Configuration);
        }
        if self.ceiling_datagrams <= ceiling {
            return Ok(self);
        }
        Ok(Self {
            floor_datagrams: self.floor_datagrams.min(ceiling),
            ceiling_datagrams: ceiling,
            ..self
        })
    }
    /// Check the documented bounds for datagrams of at most `max_datagram_bytes`.
    pub fn validate(self, max_datagram_bytes: u64) -> Result<(), Error> {
        let floor_bytes = max_datagram_bytes
            .checked_mul(MIN_FLOOR_DATAGRAMS)
            .ok_or(Error::Configuration)?;
        if max_datagram_bytes == 0
            || self.floor_datagrams < MIN_FLOOR_DATAGRAMS
            || self.floor_datagrams > self.ceiling_datagrams
            || self.ceiling_datagrams > MAX_CEILING_DATAGRAMS
            || self.floor_bytes < floor_bytes
            || self.floor_bytes > self.ceiling_bytes
            || self.ceiling_bytes > MAX_CEILING_BYTES
            || self.period < Duration::from_millis(1)
            || self.period > Duration::from_millis(100)
            || self.idle_period < self.period
            || self.idle_period > Duration::from_secs(1)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

fn rate_times(rate: u64, span: Duration) -> u64 {
    let product = u128::from(rate) * span.as_micros() / 1_000_000;
    u64::try_from(product).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Default)]
struct Bin {
    index: u64,
    bytes: u64,
    datagrams: u64,
    /// Advance of the processed packet number within the bin; it counts
    /// lost packets too, matching the sender's packet-number window.
    advance: u64,
}

#[derive(Clone, Copy, Debug)]
struct Issued {
    at: Duration,
    limit: u64,
    bytes_above: u64,
    drain_datagrams: u64,
}

/// Receiver-side observations; saturating and never authoritative.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverStatus {
    /// Highest processed data packet number plus one.
    pub processed: u64,
    /// Last issued limit.
    pub limit: u64,
    /// Last issued byte allowance.
    pub bytes_above: u64,
    /// Current drain estimate, bytes per second.
    pub drain_bytes: u64,
    /// Current drain estimate, datagrams per second.
    pub drain_datagrams: u64,
    /// Socket allowance used by the grant.
    pub allowance_bytes: u64,
    /// Credits issued.
    pub issued: u64,
    /// Whether growth is frozen for native backpressure.
    pub frozen: bool,
}

/// Receiver of data datagrams: counts processed data and issues credit.
#[derive(Debug)]
pub struct Receiver {
    config: Config,
    allowance_bytes: u64,
    processed: u64,
    data_since_issue: bool,
    bins: [Bin; BINS],
    first_bin: Option<u64>,
    serial: u64,
    issued: Option<Issued>,
    frozen: bool,
    last: Option<Duration>,
    issued_count: u64,
}
impl Receiver {
    /// `allowance_bytes` is the payload the data socket can queue without drops
    /// (half the kernel's reported receive buffer).
    pub fn new(
        config: Config,
        max_datagram_bytes: u64,
        allowance_bytes: u64,
    ) -> Result<Self, Error> {
        config.validate(max_datagram_bytes)?;
        Ok(Self {
            config,
            allowance_bytes,
            processed: 0,
            data_since_issue: false,
            bins: [Bin::default(); BINS],
            first_bin: None,
            serial: 0,
            issued: None,
            frozen: false,
            last: None,
            issued_count: 0,
        })
    }
    fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if self.last.is_some_and(|last| now < last) {
            return Err(Error::Time);
        }
        self.last = Some(now);
        Ok(())
    }
    fn bin_index(now: Duration) -> u64 {
        u64::try_from(now.as_micros() / BIN.as_micros()).unwrap_or(u64::MAX)
    }
    /// Count one finished authenticated data datagram, whatever its outcome.
    pub fn processed(&mut self, number: u64, wire_bytes: u64, now: Duration) -> Result<(), Error> {
        self.advance(now)?;
        let next = number.checked_add(1).ok_or(Error::Overflow)?;
        let advance = if self.processed == 0 {
            1
        } else {
            next.saturating_sub(self.processed)
        };
        self.processed = self.processed.max(next);
        self.data_since_issue = true;
        let index = Self::bin_index(now);
        self.first_bin.get_or_insert(index);
        let bin = &mut self.bins[(index % BINS as u64) as usize];
        if bin.index != index {
            *bin = Bin {
                index,
                bytes: 0,
                datagrams: 0,
                advance: 0,
            };
        }
        bin.bytes = bin.bytes.saturating_add(wire_bytes);
        bin.datagrams = bin.datagrams.saturating_add(1);
        bin.advance = bin.advance.saturating_add(advance);
        Ok(())
    }
    /// Freeze or release grant growth while the native queue is full.
    pub fn set_frozen(&mut self, frozen: bool) {
        self.frozen = frozen;
    }
    /// Drain estimate over the completed bins since the first processed
    /// datagram, at most 175 ms: (bytes/s, datagrams/s). Datagrams follow the
    /// processed packet number (lost packets included); bytes are scaled by
    /// the same ratio, so the grant covers what the sender must have in flight.
    ///
    /// To prevent brief ARQ/loss pauses (1 RTT of empty bins) from collapsing
    /// the grant and pacing rate, the estimate takes the maximum of the full
    /// completed-bin average and the best contiguous two-bin (50 ms) rate while
    /// still returning `(0, 0)` once all completed bins are empty.
    pub fn drain(&self, now: Duration) -> (u64, u64) {
        let current = Self::bin_index(now);
        let Some(observed) = self.first_bin else {
            return (0, 0);
        };
        let first = current.saturating_sub(BINS as u64 - 1).max(observed);
        if first >= current {
            return (0, 0);
        }
        let scale_bytes = |received_bytes: u64, received: u64, advance: u64| -> u64 {
            if received == 0 {
                0
            } else {
                u64::try_from(
                    u128::from(received_bytes) * u128::from(advance.max(received))
                        / u128::from(received),
                )
                .unwrap_or(u64::MAX)
            }
        };
        let (received_bytes, received, datagrams) = self
            .bins
            .iter()
            .filter(|bin| bin.index >= first && bin.index < current)
            .fold((0_u64, 0_u64, 0_u64), |(b, r, a), bin| {
                (
                    b.saturating_add(bin.bytes),
                    r.saturating_add(bin.datagrams),
                    a.saturating_add(bin.advance),
                )
            });
        if received == 0 {
            return (0, 0);
        }
        let bytes = scale_bytes(received_bytes, received, datagrams);
        let span = u128::from(current - first) * BIN.as_micros();
        let per_second = |value: u64, window_us: u128| {
            u64::try_from(u128::from(value) * 1_000_000 / window_us).unwrap_or(u64::MAX)
        };
        let mut best_bytes = per_second(bytes, span);
        let mut best_datagrams = per_second(datagrams, span);
        if current - first >= 2 {
            let pair_span = 2 * BIN.as_micros();
            for idx in first..(current - 1) {
                let b0 = self.bins[(idx % BINS as u64) as usize];
                let b1 = self.bins[((idx + 1) % BINS as u64) as usize];
                let (mut wb, mut wr, mut wa) = (0_u64, 0_u64, 0_u64);
                if b0.index == idx {
                    wb = wb.saturating_add(b0.bytes);
                    wr = wr.saturating_add(b0.datagrams);
                    wa = wa.saturating_add(b0.advance);
                }
                if b1.index == idx + 1 {
                    wb = wb.saturating_add(b1.bytes);
                    wr = wr.saturating_add(b1.datagrams);
                    wa = wa.saturating_add(b1.advance);
                }
                if wr > 0 {
                    let scaled = scale_bytes(wb, wr, wa);
                    best_bytes = best_bytes.max(per_second(scaled, pair_span));
                    best_datagrams = best_datagrams.max(per_second(wa, pair_span));
                }
            }
        }
        (best_bytes, best_datagrams)
    }
    fn allowance_datagrams(&self, now: Duration) -> u64 {
        let current = Self::bin_index(now);
        let bytes_per_datagram = match self.first_bin {
            Some(observed) => {
                let first = current.saturating_sub(BINS as u64 - 1).max(observed);
                let (received_bytes, received) = self
                    .bins
                    .iter()
                    .filter(|bin| bin.index >= first && bin.index < current)
                    .fold((0_u64, 0_u64), |(b, r), bin| {
                        (b.saturating_add(bin.bytes), r.saturating_add(bin.datagrams))
                    });
                if received == 0 {
                    ALLOWANCE_BYTES_PER_DATAGRAM
                } else {
                    (received_bytes / received).clamp(
                        MIN_ALLOWANCE_BYTES_PER_DATAGRAM,
                        ALLOWANCE_BYTES_PER_DATAGRAM,
                    )
                }
            }
            None => ALLOWANCE_BYTES_PER_DATAGRAM,
        };
        (self.allowance_bytes / bytes_per_datagram).saturating_add(1)
    }
    /// Current grant: (limit, bytes_above). The limit never decreases.
    pub fn grant(&self, now: Duration, min_rtt: Option<Duration>) -> (u64, u64) {
        if self.frozen
            && let Some(issued) = self.issued
        {
            return (issued.limit.max(self.processed), issued.bytes_above);
        }
        let (drain_bytes, drain_datagrams) = self.drain(now);
        // The sender sees `processed` up to one Credit period late.
        let rtt = min_rtt
            .unwrap_or(Duration::ZERO)
            .saturating_add(self.config.period);
        let bytes = rate_times(drain_bytes, rtt)
            .saturating_add(self.allowance_bytes)
            .clamp(self.config.floor_bytes, self.config.ceiling_bytes);
        let datagrams = rate_times(drain_datagrams, rtt)
            .saturating_add(self.allowance_datagrams(now))
            .clamp(self.config.floor_datagrams, self.config.ceiling_datagrams);
        let limit = self.processed.saturating_add(datagrams);
        (
            self.issued.map_or(limit, |issued| issued.limit.max(limit)),
            bytes,
        )
    }
    /// When the next Credit is due; `Some(now)` or earlier means due now.
    /// Nothing is due before the first processed data datagram: the sender
    /// starts with the configured floor, so an idle session sends no credit.
    pub fn due(&self, now: Duration, min_rtt: Option<Duration>) -> Option<Duration> {
        let Some(issued) = self.issued else {
            return (self.processed != 0).then_some(now);
        };
        let (limit, _) = self.grant(now, min_rtt);
        let window = limit.saturating_sub(self.processed).max(1);
        if limit.saturating_sub(issued.limit) >= window.div_ceil(4) {
            return Some(now);
        }
        let idle = issued.at.saturating_add(self.config.idle_period);
        if self.data_since_issue {
            Some(issued.at.saturating_add(self.config.period).min(idle))
        } else if issued.drain_datagrams > 0 {
            if self.drain(now).1 == 0 {
                // Transitioned from active to idle since the last Credit: notify the
                // sender immediately so any lost tail can be declared without waiting
                // for the remaining idle heartbeat interval.
                Some(now)
            } else {
                let empty_at = self
                    .bins
                    .iter()
                    .filter(|bin| bin.datagrams > 0)
                    .map(|bin| bin.index)
                    .max()
                    .and_then(|last| last.checked_add(BINS as u64))
                    .and_then(|empty_bin| empty_bin.checked_mul(BIN.as_micros() as u64))
                    .map(Duration::from_micros);
                Some(empty_at.map_or(idle, |at| at.min(idle)))
            }
        } else {
            Some(idle)
        }
    }
    /// Issue the next Credit and record it as sent.
    pub fn issue(&mut self, now: Duration, min_rtt: Option<Duration>) -> Result<Credit, Error> {
        self.advance(now)?;
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let (limit, bytes_above) = self.grant(now, min_rtt);
        let (drain_bytes, drain_datagrams) = self.drain(now);
        let credit = Credit {
            serial,
            processed: self.processed,
            limit,
            bytes_above,
            drain_bytes,
            drain_datagrams,
        };
        credit.check()?;
        self.serial = serial;
        self.issued = Some(Issued {
            at: now,
            limit,
            bytes_above,
            drain_datagrams,
        });
        self.data_since_issue = false;
        self.issued_count = self.issued_count.saturating_add(1);
        Ok(credit)
    }
    /// Observation only.
    pub fn status(&self, now: Duration) -> ReceiverStatus {
        let (drain_bytes, drain_datagrams) = self.drain(now);
        ReceiverStatus {
            processed: self.processed,
            limit: self.issued.map_or(0, |issued| issued.limit),
            bytes_above: self.issued.map_or(0, |issued| issued.bytes_above),
            drain_bytes,
            drain_datagrams,
            allowance_bytes: self.allowance_bytes,
            issued: self.issued_count,
            frozen: self.frozen,
        }
    }
}

/// Outcome of applying a peer Credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Applied {
    /// Newer than any accepted Credit.
    Accepted,
    /// Not newer; ignored.
    Stale,
}

/// Whether the next data datagram may be prepared now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gate {
    /// Within the window and the pacing bucket.
    Open,
    /// Outside the granted window; wait for a newer Credit.
    Credit,
    /// Within the window; the pacing bucket refills at this time.
    Pacing(Duration),
}

#[derive(Clone, Copy, Debug)]
struct Flight {
    number: u64,
    bytes: u64,
    sent_at: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
struct RttBin {
    index: u64,
    min: Option<Duration>,
}

/// Sender-side observations; saturating and never authoritative.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SenderStatus {
    /// Effective limit (exclusive data packet number).
    pub limit: u64,
    /// Datagram window of the newest Credit (`limit - processed`); the gate
    /// keeps in-flight datagrams below it.
    pub window: u64,
    /// Effective byte allowance above the peer's processed packet.
    pub bytes_above: u64,
    /// Peer's highest processed data packet number plus one.
    pub peer_processed: u64,
    /// Data wire bytes sent above `peer_processed`.
    pub inflight_bytes: u64,
    /// Data datagrams sent above `peer_processed`.
    pub inflight_datagrams: u64,
    /// Peer drain estimate, bytes per second.
    pub peer_drain_bytes: u64,
    /// Effective data pacing rate, bytes per second.
    pub pacing_rate: u64,
    /// Credits accepted.
    pub accepted: u64,
    /// Credits ignored as stale.
    pub stale: u64,
    /// Gate checks refused for credit.
    pub credit_blocked: u64,
    /// Gate checks refused for pacing.
    pub pacing_blocked: u64,
    /// In-flight datagrams declared lost after an idle receiver reported no
    /// progress (they would otherwise hold the window shut).
    pub declared_lost: u64,
    /// The peer's record-receive range this sender keeps data within.
    pub range: u64,
    /// Gate checks refused because data would leave half the receive range.
    pub range_blocked: u64,
    /// Data datagrams sent into the upper half as one-per-Credit probes.
    pub range_probes: u64,
    /// Current minimum RTT sample, if any.
    pub min_rtt: Option<Duration>,
}

/// Sender of data datagrams: applies peer Credit, gates and paces data.
#[derive(Debug)]
pub struct Sender {
    /// The peer's record-receive range; data stays within half of it above
    /// `peer_processed`, and the upper half is a probe reserve.
    range: u64,
    /// One data datagram may enter the reserve per accepted Credit, so the
    /// receiver sees data again after an outage and `processed` can move.
    probe: bool,
    max_datagram_bytes: u64,
    period: Duration,
    idle_period: Duration,
    configured_rate: u64,
    burst: u64,
    newest_serial: u64,
    limit: u64,
    /// Datagram window of the newest Credit: unprocessed datagrams the peer
    /// accepts in flight. The gate compares the in-flight ring with it rather
    /// than packet numbers with `limit`, so declared losses free space.
    window: u64,
    bytes_above: u64,
    peer_processed: u64,
    peer_drain_bytes: u64,
    ring: VecDeque<Flight>,
    capacity: usize,
    inflight_bytes: u64,
    rtt: [RttBin; RTT_BINS],
    rate: u64,
    tokens: u64,
    refilled: Option<Duration>,
    last: Option<Duration>,
    status: SenderStatus,
}
impl Sender {
    /// `first_number` is the first data packet number this sender will use;
    /// `configured_rate` and `burst_bytes` are the session's send policy.
    /// `range` is how far past its highest accepted packet number the peer's
    /// record receiver can open (`min(packets_per_key, max_forward_packets)`);
    /// it must be at least [`Config::minimum_range`].
    pub fn new(
        config: Config,
        max_datagram_bytes: u64,
        first_number: u64,
        configured_rate: u64,
        burst_bytes: u64,
        range: u64,
    ) -> Result<Self, Error> {
        config.validate(max_datagram_bytes)?;
        if configured_rate == 0 || range < config.minimum_range()? {
            return Err(Error::Configuration);
        }
        let capacity =
            usize::try_from(config.ceiling_datagrams).map_err(|_| Error::Configuration)?;
        let burst = burst_bytes
            .min(max_datagram_bytes.saturating_mul(PACING_BURST_DATAGRAMS))
            .max(max_datagram_bytes);
        Ok(Self {
            max_datagram_bytes,
            range,
            probe: false,
            period: config.period,
            idle_period: config.idle_period,
            configured_rate,
            burst,
            newest_serial: 0,
            limit: first_number
                .checked_add(config.floor_datagrams)
                .ok_or(Error::Overflow)?,
            window: config.floor_datagrams,
            bytes_above: config.floor_bytes,
            peer_processed: first_number,
            peer_drain_bytes: 0,
            ring: VecDeque::with_capacity(capacity),
            capacity,
            inflight_bytes: 0,
            rtt: [RttBin::default(); RTT_BINS],
            rate: configured_rate,
            tokens: burst,
            refilled: None,
            last: None,
            status: SenderStatus::default(),
        })
    }
    fn advance(&mut self, now: Duration) -> Result<(), Error> {
        if self.last.is_some_and(|last| now < last) {
            return Err(Error::Time);
        }
        self.last = Some(now);
        if let Some(at) = self.refilled {
            let elapsed = now.saturating_sub(at);
            self.tokens = self
                .tokens
                .saturating_add(rate_times(self.rate, elapsed))
                .min(self.burst);
        }
        self.refilled = Some(now);
        Ok(())
    }
    /// Apply one authenticated peer Credit.
    pub fn apply(&mut self, credit: Credit, now: Duration) -> Result<Applied, Error> {
        credit.check()?;
        self.advance(now)?;
        if credit.serial <= self.newest_serial {
            self.status.stale = self.status.stale.saturating_add(1);
            return Ok(Applied::Stale);
        }
        self.newest_serial = credit.serial;
        self.limit = self.limit.max(credit.limit);
        self.window = credit.limit - credit.processed;
        self.bytes_above = credit.bytes_above;
        self.peer_drain_bytes = credit.drain_bytes;
        if credit.processed <= self.peer_processed && credit.drain_datagrams == 0 {
            // An idle receiver with no progress has nothing queued, so data
            // sent longer than one round trip and one Credit period ago was
            // lost. Without this, losing the whole in-flight tail would keep
            // `processed`, and with it the window, frozen for good.
            let wait = self
                .min_rtt(now)
                .unwrap_or(self.idle_period)
                .saturating_add(self.period);
            let cutoff = now.saturating_sub(wait);
            while let Some(front) = self.ring.front().copied() {
                if front.sent_at > cutoff {
                    break;
                }
                self.ring.pop_front();
                self.inflight_bytes = self.inflight_bytes.saturating_sub(front.bytes);
                self.status.declared_lost = self.status.declared_lost.saturating_add(1);
            }
        }
        if credit.processed > self.peer_processed {
            self.peer_processed = credit.processed;
            let mut newest = None;
            while let Some(front) = self.ring.front().copied() {
                if front.number >= credit.processed {
                    break;
                }
                self.ring.pop_front();
                self.inflight_bytes = self.inflight_bytes.saturating_sub(front.bytes);
                newest = Some(front);
            }
            if let Some(flight) = newest {
                self.sample(now.saturating_sub(flight.sent_at), now);
            }
        }
        self.rate = self.pacing_rate(credit, now);
        self.probe = true;
        self.status.accepted = self.status.accepted.saturating_add(1);
        Ok(Applied::Accepted)
    }
    /// Spread the byte window over one round trip (plus the Credit period the
    /// sender's view lags), never below 5/4 of the drain rate, so a window
    /// opened by one Credit leaves as a smooth flow instead of a burst while
    /// the receiver's allowance still lets the rate grow.
    fn pacing_rate(&self, credit: Credit, now: Duration) -> u64 {
        if credit.drain_bytes == 0 {
            return self.configured_rate;
        }
        let floor =
            u128::from(credit.drain_bytes) * u128::from(PACING_GAIN.0) / u128::from(PACING_GAIN.1);
        let paced = match self.min_rtt(now) {
            Some(rtt) => {
                let span = rtt.saturating_add(self.period).as_micros().max(1);
                floor.max(u128::from(credit.bytes_above) * 1_000_000 / span)
            }
            None => u128::from(credit.drain_bytes) * u128::from(PACING_GAIN_UNTIMED),
        };
        u64::try_from(paced)
            .unwrap_or(u64::MAX)
            .clamp(self.max_datagram_bytes, self.configured_rate)
    }
    fn sample(&mut self, rtt: Duration, now: Duration) {
        let index = u64::try_from(now.as_micros() / RTT_BIN.as_micros()).unwrap_or(u64::MAX);
        let bin = &mut self.rtt[(index % RTT_BINS as u64) as usize];
        if bin.index != index {
            *bin = RttBin { index, min: None };
        }
        bin.min = Some(bin.min.map_or(rtt, |min| min.min(rtt)));
    }
    /// Minimum RTT sample over the last ten seconds.
    pub fn min_rtt(&self, now: Duration) -> Option<Duration> {
        let current = u64::try_from(now.as_micros() / RTT_BIN.as_micros()).unwrap_or(u64::MAX);
        let first = current.saturating_sub(RTT_BINS as u64 - 1);
        self.rtt
            .iter()
            .filter(|bin| bin.index >= first && bin.index <= current)
            .filter_map(|bin| bin.min)
            .min()
    }
    /// Whether data datagram `number` may be prepared at `now`.
    pub fn gate(&mut self, number: u64, now: Duration) -> Result<Gate, Error> {
        self.advance(now)?;
        let ahead = number.saturating_sub(self.peer_processed);
        // `range - 1` ahead is the last number the peer can open if everything
        // since `processed` was lost (docs/modules/receiver-credit.md). Normal
        // data stays in the lower half; the upper half admits one probe per
        // accepted Credit so a lost tail cannot freeze `processed` for good.
        if ahead >= self.range.saturating_sub(1) || (ahead >= self.range / 2 && !self.probe) {
            self.status.range_blocked = self.status.range_blocked.saturating_add(1);
            return Ok(Gate::Credit);
        }
        if self.ring.len() as u64 >= self.window
            || self.ring.len() >= self.capacity
            || self.inflight_bytes.saturating_add(self.max_datagram_bytes) > self.bytes_above
        {
            self.status.credit_blocked = self.status.credit_blocked.saturating_add(1);
            return Ok(Gate::Credit);
        }
        if self.tokens < self.max_datagram_bytes {
            self.status.pacing_blocked = self.status.pacing_blocked.saturating_add(1);
            let missing = self.max_datagram_bytes - self.tokens;
            let micros = u128::from(missing) * 1_000_000 / u128::from(self.rate.max(1));
            let wait = Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX).max(1));
            return Ok(Gate::Pacing(now.saturating_add(wait)));
        }
        Ok(Gate::Open)
    }
    /// Record one sent data datagram, in increasing packet-number order.
    pub fn sent(&mut self, number: u64, wire_bytes: u64, now: Duration) -> Result<(), Error> {
        self.advance(now)?;
        if self.ring.len() >= self.capacity
            || self.ring.back().is_some_and(|back| back.number >= number)
        {
            return Err(Error::Window);
        }
        if number >= self.peer_processed {
            self.ring.push_back(Flight {
                number,
                bytes: wire_bytes,
                sent_at: now,
            });
            self.inflight_bytes = self.inflight_bytes.saturating_add(wire_bytes);
        }
        if number.saturating_sub(self.peer_processed) >= self.range / 2 && self.probe {
            self.probe = false;
            self.status.range_probes = self.status.range_probes.saturating_add(1);
        }
        self.tokens = self.tokens.saturating_sub(wire_bytes);
        Ok(())
    }
    /// Gate checks refused because data would leave half the receive range.
    pub fn range_blocked(&self) -> u64 {
        self.status.range_blocked
    }
    /// Observation only.
    pub fn status(&self, now: Duration) -> SenderStatus {
        SenderStatus {
            limit: self.limit,
            window: self.window,
            bytes_above: self.bytes_above,
            peer_processed: self.peer_processed,
            inflight_bytes: self.inflight_bytes,
            inflight_datagrams: self.ring.len() as u64,
            peer_drain_bytes: self.peer_drain_bytes,
            pacing_rate: self.rate,
            min_rtt: self.min_rtt(now),
            range: self.range,
            ..self.status
        }
    }
}

#[cfg(test)]
mod tests;

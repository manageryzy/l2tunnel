//! Bounded measurements of actual physical payments, independent of native custody.
use super::{AckBlock, Error};
use std::collections::VecDeque;

/// Observed physical receipt timing; all values use caller-supplied microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Whether new positive physical receipts update the timeout.
    pub adaptive: bool,
    /// Number of distinct ACK blocks contributing a new physical sample.
    pub samples: u64,
    /// Smoothed round-trip time, including receiver feedback service.
    pub srtt_us: Option<u64>,
    /// Smoothed absolute deviation of the round-trip samples.
    pub rttvar_us: Option<u64>,
    /// Current bounded timeout for physical payments.
    pub rto_us: u64,
}

struct Payment {
    sequence: u64,
    at: u64,
    observed: bool,
}

pub(super) struct Tracker {
    history: VecDeque<Payment>,
    limit: usize,
    min: u64,
    max: u64,
    granularity: u64,
    timing: Timing,
}

impl Tracker {
    pub(super) fn new(
        limit: usize,
        initial: u64,
        min: u64,
        max: u64,
        granularity: u64,
    ) -> Result<Self, Error> {
        if min == 0 || min > initial || initial > max || granularity == 0 || granularity > max {
            return Err(Error::Invalid);
        }
        let mut history = VecDeque::new();
        history
            .try_reserve_exact(limit)
            .map_err(|_| Error::Allocation)?;
        Ok(Self {
            history,
            limit,
            min,
            max,
            granularity,
            timing: Timing {
                adaptive: true,
                samples: 0,
                srtt_us: None,
                rttvar_us: None,
                rto_us: initial,
            },
        })
    }

    pub(super) fn sent(&mut self, sequence: u64, at: u64) {
        if self.history.len() == self.limit {
            self.history.pop_front();
        }
        self.history.push_back(Payment {
            sequence,
            at,
            observed: false,
        });
    }

    pub(super) fn timing(&self) -> Timing {
        self.timing
    }

    /// Preview without consuming the sample so deadline overflow remains transactional.
    pub(super) fn propose(&self, block: &AckBlock, now: u64) -> Option<Timing> {
        let payment = self
            .history
            .iter()
            .rev()
            .find(|p| !p.observed && block.acknowledges(p.sequence))?;
        let sample = u128::from(now.checked_sub(payment.at)?.max(1));
        let (srtt, variance) = match (self.timing.srtt_us, self.timing.rttvar_us) {
            (Some(srtt), Some(var)) => {
                let old = u128::from(srtt);
                (
                    (7 * old + sample + 4) / 8,
                    (3 * u128::from(var) + old.abs_diff(sample) + 2) / 4,
                )
            }
            _ => (sample, sample.div_ceil(2)),
        };
        let rto = (srtt + (4 * variance).max(u128::from(self.granularity)))
            .clamp(u128::from(self.min), u128::from(self.max));
        Some(Timing {
            adaptive: true,
            samples: self.timing.samples.saturating_add(1),
            srtt_us: Some(srtt as u64),
            rttvar_us: Some(variance as u64),
            rto_us: rto as u64,
        })
    }

    pub(super) fn commit(&mut self, block: &AckBlock, timing: Timing) {
        for payment in &mut self.history {
            if block.acknowledges(payment.sequence) {
                payment.observed = true;
            }
        }
        self.timing = timing;
    }
}

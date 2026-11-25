//! Bounded client-side metrics history and derived rates. Rates come only from
//! two samples of the same series; a new generation, a service restart or a
//! decreasing counter starts a new series instead of producing a negative rate.
use l2tunnel_client_core::local::Metrics;
use std::collections::VecDeque;

/// Samples kept: ten minutes at one sample per second.
pub const HISTORY: usize = 600;

/// One retained sample of the counters the charts use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Sample {
    /// Service-monotonic milliseconds.
    pub ms: u64,
    /// Series identity: service instance and session generation.
    pub series: (u64, u64),
    /// Wire bytes sent.
    pub sent_bytes: Option<u64>,
    /// Wire packets sent.
    pub sent_packets: Option<u64>,
    /// Wire packets received.
    pub received_packets: Option<u64>,
    /// Device packets read (toward the peer).
    pub device_read: Option<u64>,
    /// Device packets written (from the peer).
    pub device_written: Option<u64>,
}
impl Sample {
    /// Extract the charted counters from one metrics reply of `service`.
    pub fn of(service: u64, metrics: &Metrics) -> Self {
        Self {
            ms: metrics.sampled_ms,
            series: (service, metrics.generation),
            sent_bytes: metrics.wire.map(|wire| wire.sent_bytes),
            sent_packets: metrics.wire.map(|wire| wire.sent_packets),
            received_packets: metrics.wire.map(|wire| wire.received_packets),
            device_read: metrics.device.map(|device| device.read_packets),
            device_written: metrics.device.map(|device| device.written_packets),
        }
    }
}

/// A charted rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rate {
    /// Wire bits per second sent.
    SentBits,
    /// Wire packets per second sent.
    SentPackets,
    /// Wire packets per second received.
    ReceivedPackets,
    /// Device packets per second read (upload).
    DeviceRead,
    /// Device packets per second written (download).
    DeviceWritten,
}
impl Rate {
    fn counter(self, sample: &Sample) -> Option<u64> {
        match self {
            Self::SentBits => sample.sent_bytes,
            Self::SentPackets => sample.sent_packets,
            Self::ReceivedPackets => sample.received_packets,
            Self::DeviceRead => sample.device_read,
            Self::DeviceWritten => sample.device_written,
        }
    }
    fn scale(self) -> f64 {
        if self == Self::SentBits { 8.0 } else { 1.0 }
    }
}

/// Bounded sample history.
#[derive(Debug, Default)]
pub struct History {
    samples: VecDeque<Sample>,
}
impl History {
    /// Append a sample; a duplicate or older time is ignored.
    pub fn push(&mut self, sample: Sample) {
        if let Some(last) = self.samples.back()
            && last.series == sample.series
            && sample.ms <= last.ms
        {
            return;
        }
        if self.samples.len() == HISTORY {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }
    /// Forget everything (new attachment).
    pub fn clear(&mut self) {
        self.samples.clear();
    }
    /// Retained samples.
    pub fn len(&self) -> usize {
        self.samples.len()
    }
    /// Whether nothing is retained.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
    fn between(rate: Rate, older: &Sample, newer: &Sample) -> Option<f64> {
        if older.series != newer.series || newer.ms <= older.ms {
            return None;
        }
        let delta = Rate::counter(rate, newer)?.checked_sub(Rate::counter(rate, older)?)?;
        let seconds = (newer.ms - older.ms) as f64 / 1000.0;
        Some(delta as f64 * rate.scale() / seconds)
    }
    /// Rate between the two newest samples, when they share a series.
    pub fn latest(&self, rate: Rate) -> Option<f64> {
        let mut newest = self.samples.iter().rev();
        let newer = newest.next()?;
        Self::between(rate, newest.next()?, newer)
    }
    /// Per-interval rates of the current series over the last `seconds`,
    /// oldest first; `None` marks an unreported or decreasing counter.
    pub fn series(&self, rate: Rate, seconds: u64) -> Vec<Option<f64>> {
        let Some(last) = self.samples.back() else {
            return Vec::new();
        };
        let from = last.ms.saturating_sub(seconds.saturating_mul(1000));
        let window: Vec<&Sample> = self
            .samples
            .iter()
            .filter(|sample| sample.series == last.series && sample.ms >= from)
            .collect();
        window
            .windows(2)
            .map(|pair| Self::between(rate, pair[0], pair[1]))
            .collect()
    }
}

/// Human rate text: bits as kb/Mb/Gb per second, packets as pkt/s.
pub fn rate_text(rate: Rate, value: Option<f64>) -> String {
    let Some(value) = value else {
        return "—".into();
    };
    if rate == Rate::SentBits {
        match value {
            v if v >= 1e9 => format!("{:.2} Gb/s", v / 1e9),
            v if v >= 1e6 => format!("{:.1} Mb/s", v / 1e6),
            v if v >= 1e3 => format!("{:.1} kb/s", v / 1e3),
            v => format!("{v:.0} b/s"),
        }
    } else {
        format!("{value:.0} pkt/s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ms: u64, generation: u64, sent: u64) -> Sample {
        Sample {
            ms,
            series: (7, generation),
            sent_bytes: Some(sent),
            sent_packets: Some(sent / 100),
            ..Sample::default()
        }
    }

    #[test]
    fn rates_need_two_samples_of_one_series() {
        let mut history = History::default();
        assert_eq!(history.latest(Rate::SentBits), None);
        history.push(sample(1_000, 1, 0));
        assert_eq!(history.latest(Rate::SentBits), None);
        history.push(sample(2_000, 1, 125_000));
        assert_eq!(history.latest(Rate::SentBits), Some(1_000_000.0));
        assert_eq!(
            rate_text(Rate::SentBits, history.latest(Rate::SentBits)),
            "1.0 Mb/s"
        );
        // A duplicate time is ignored; a new generation breaks the series.
        history.push(sample(2_000, 1, 999_999));
        assert_eq!(history.len(), 2);
        history.push(sample(3_000, 2, 10));
        assert_eq!(history.latest(Rate::SentBits), None);
        // A decreasing counter in the same series yields no rate.
        history.push(sample(4_000, 2, 5));
        assert_eq!(history.latest(Rate::SentBits), None);
        assert_eq!(history.latest(Rate::ReceivedPackets), None, "unreported");
        assert_eq!(rate_text(Rate::DeviceRead, None), "—");
    }

    #[test]
    fn history_is_bounded_and_series_marks_breaks() {
        let mut history = History::default();
        for second in 0..(HISTORY as u64 + 10) {
            history.push(sample(second * 1000, 1, second * 1000));
        }
        assert_eq!(history.len(), HISTORY);
        let series = history.series(Rate::SentBits, 5);
        assert_eq!(series.len(), 5);
        assert!(series.iter().all(|value| *value == Some(8_000.0)));
        history.push(sample(u64::MAX / 2, 9, 0));
        assert_eq!(history.series(Rate::SentBits, 5), Vec::<Option<f64>>::new());
    }
}

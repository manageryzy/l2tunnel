//! Speed and ping tests through the tunnel (TT-01..TT-04, owner decisions
//! 2026-11-24, `docs/modules/tunnel-tests.md`): request and state types of
//! the local API. The traffic is in-process TCP and ICMP (smoltcp) carried
//! as flagged test packets through the runtime's native path; it never
//! reaches a TUN/TAP device or the host network stack.
use serde::{Deserialize, Serialize};

/// Most parallel speed-test streams.
pub const MAX_STREAMS: u8 = 8;
/// Shortest and longest speed test.
pub const DURATION_MS: std::ops::RangeInclusive<u32> = 1_000..=30_000;
/// Most ping probes.
pub const MAX_PINGS: u16 = 100;
/// Shortest and longest gap between pings.
pub const PING_INTERVAL_MS: std::ops::RangeInclusive<u32> = 100..=1_000;
/// Most samples (and ping round trips) kept in a state.
pub const SAMPLE_LIMIT: usize = 100;

/// Speed-test direction, seen from the tester.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Tester sends; the peer counts what arrived.
    Upload,
    /// Peer sends; the tester counts what arrived.
    Download,
}

/// One requested test.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TestRequest {
    /// TCP streaming throughput.
    Speed {
        /// Upload or download.
        direction: Direction,
        /// Parallel TCP streams, 1 through [`MAX_STREAMS`].
        streams: u8,
        /// Within [`DURATION_MS`].
        duration_ms: u32,
    },
    /// ICMP echo round trips.
    Ping {
        /// Probes, 1 through [`MAX_PINGS`].
        count: u16,
        /// Within [`PING_INTERVAL_MS`].
        interval_ms: u32,
    },
}
impl TestRequest {
    /// Check the bounds.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Speed {
                streams,
                duration_ms,
                ..
            } => {
                if !(1..=MAX_STREAMS).contains(streams) {
                    return Err("streams must be 1 through 8");
                }
                if !DURATION_MS.contains(duration_ms) {
                    return Err("duration must be 1 through 30 seconds");
                }
            }
            Self::Ping { count, interval_ms } => {
                if !(1..=MAX_PINGS).contains(count) {
                    return Err("count must be 1 through 100");
                }
                if !PING_INTERVAL_MS.contains(interval_ms) {
                    return Err("interval must be 100 through 1000 ms");
                }
            }
        }
        Ok(())
    }
    /// `speed` or `ping`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Speed { .. } => "speed",
            Self::Ping { .. } => "ping",
        }
    }
}

/// Lifecycle of a test.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestPhase {
    /// Still measuring.
    Running,
    /// Finished with a result.
    Completed,
    /// Ended by an error.
    Failed,
    /// Cancelled locally.
    Cancelled,
}

/// Ping results.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingResult {
    /// Probes sent.
    pub sent: u16,
    /// Replies received in time.
    pub received: u16,
    /// Fastest round trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_us: Option<u32>,
    /// Mean round trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avg_us: Option<u32>,
    /// Slowest round trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_us: Option<u32>,
    /// Round trip per probe in order; `null` is a lost probe.
    pub rtts_us: Vec<Option<u32>>,
}
impl PingResult {
    /// Recompute min/avg/max from `rtts_us`.
    pub fn summarize(&mut self) {
        let answered: Vec<u32> = self.rtts_us.iter().flatten().copied().collect();
        self.received = u16::try_from(answered.len()).unwrap_or(u16::MAX);
        self.min_us = answered.iter().min().copied();
        self.max_us = answered.iter().max().copied();
        self.avg_us = (!answered.is_empty()).then(|| {
            let total: u64 = answered.iter().map(|value| u64::from(*value)).sum();
            u32::try_from(total / answered.len() as u64).unwrap_or(u32::MAX)
        });
    }
    /// Lost share in percent.
    pub fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        100.0 * f64::from(self.sent.saturating_sub(self.received)) / f64::from(self.sent)
    }
}

/// One test's state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestState {
    /// Service-local test number.
    pub id: u64,
    /// `speed` or `ping`.
    pub kind: String,
    /// Lifecycle.
    pub state: TestPhase,
    /// Speed direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    /// Speed streams.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<u8>,
    /// Requested speed duration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u32>,
    /// Time since start.
    pub elapsed_ms: u64,
    /// Bytes counted (upload: confirmed by the peer at the end).
    pub bytes: u64,
    /// Mean rate so far, or the final rate.
    pub bits_per_second: u64,
    /// Rate per second of the test (speed).
    pub samples: Vec<u64>,
    /// Ping results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping: Option<PingResult>,
    /// Why it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Reply field of the test actions.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestReply {
    /// Requested or latest test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<TestState>,
}

/// A rate in words, e.g. `94.2 Mbit/s`.
pub fn rate_text(bits_per_second: u64) -> String {
    let value = bits_per_second as f64;
    if value >= 1e9 {
        format!("{:.2} Gbit/s", value / 1e9)
    } else if value >= 1e6 {
        format!("{:.1} Mbit/s", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kbit/s", value / 1e3)
    } else {
        format!("{bits_per_second} bit/s")
    }
}

/// One line describing a test, as the CLI prints it.
pub fn test_text(state: &TestState) -> String {
    let phase = match state.state {
        TestPhase::Running => "running",
        TestPhase::Completed => "completed",
        TestPhase::Failed => "failed",
        TestPhase::Cancelled => "cancelled",
    };
    let mut text = format!("test {} ({}): {phase}", state.id, state.kind);
    match &state.ping {
        Some(ping) => {
            text += &format!(
                ", {}/{} replies ({:.0}% loss)",
                ping.received,
                ping.sent,
                ping.loss_percent()
            );
            if let (Some(min), Some(avg), Some(max)) = (ping.min_us, ping.avg_us, ping.max_us) {
                text += &format!(
                    ", rtt min/avg/max {:.2}/{:.2}/{:.2} ms",
                    f64::from(min) / 1e3,
                    f64::from(avg) / 1e3,
                    f64::from(max) / 1e3
                );
            }
        }
        None => {
            let direction = match state.direction {
                Some(Direction::Download) => "download",
                _ => "upload",
            };
            text += &format!(
                ", {direction} {} over {} stream(s), {} bytes in {:.1} s",
                rate_text(state.bits_per_second),
                state.streams.unwrap_or(1),
                state.bytes,
                state.elapsed_ms as f64 / 1e3
            );
        }
    }
    if let Some(error) = &state.error {
        text += &format!(" [{error}]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_strict_and_bounded() {
        let speed: Result<TestRequest, _> = serde_json::from_str(
            r#"{"kind":"speed","direction":"download","streams":4,"duration_ms":10000}"#,
        );
        assert!(speed.as_ref().is_ok_and(|test| test.validate().is_ok()));
        for text in [
            r#"{"kind":"speed","direction":"upload","streams":0,"duration_ms":10000}"#,
            r#"{"kind":"speed","direction":"upload","streams":9,"duration_ms":10000}"#,
            r#"{"kind":"speed","direction":"upload","streams":1,"duration_ms":999}"#,
            r#"{"kind":"ping","count":0,"interval_ms":200}"#,
            r#"{"kind":"ping","count":5,"interval_ms":50}"#,
        ] {
            let request: Result<TestRequest, _> = serde_json::from_str(text);
            assert!(
                request.as_ref().is_ok_and(|test| test.validate().is_err()),
                "{text}"
            );
        }
        for text in [
            r#"{"kind":"ping","count":5,"interval_ms":200,"extra":1}"#,
            r#"{"kind":"speed","direction":"upload","streams":1,"duration_ms":5000,"to":"10.0.0.1"}"#,
            r#"{"kind":"flood","count":5}"#,
        ] {
            assert!(serde_json::from_str::<TestRequest>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn ping_summary_and_texts() {
        let mut ping = PingResult {
            sent: 4,
            rtts_us: vec![Some(1_000), None, Some(3_000), Some(2_000)],
            ..PingResult::default()
        };
        ping.summarize();
        assert_eq!(
            (ping.received, ping.min_us, ping.avg_us, ping.max_us),
            (3, Some(1_000), Some(2_000), Some(3_000))
        );
        assert!((ping.loss_percent() - 25.0).abs() < 1e-9);
        assert_eq!(rate_text(94_200_000), "94.2 Mbit/s");
        assert_eq!(rate_text(1_500_000_000), "1.50 Gbit/s");
        let state = TestState {
            id: 2,
            kind: "ping".into(),
            state: TestPhase::Completed,
            direction: None,
            streams: None,
            duration_ms: None,
            elapsed_ms: 800,
            bytes: 0,
            bits_per_second: 0,
            samples: Vec::new(),
            ping: Some(ping),
            error: None,
        };
        assert_eq!(
            test_text(&state),
            "test 2 (ping): completed, 3/4 replies (25% loss), \
             rtt min/avg/max 1.00/2.00/3.00 ms"
        );
    }
}

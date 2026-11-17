//! Sampled public maintained transport facts, never queue occupancy or authority.
use std::io::{self, Write};

/// Opt-in diagnostic sampling cadence, independent of every protocol timer.
const SAMPLE_INTERVAL_US: u64 = 100_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Sample {
    pub rtt_us: u64,
    pub cwnd_bytes: u64,
    pub congestion_events: u64,
    pub lost_quic_packets: u64,
    pub lost_quic_bytes: u64,
    pub sent_quic_packets: u64,
    pub udp_tx_datagrams: u64,
    pub udp_rx_datagrams: u64,
    pub udp_tx_payload_bytes: u64,
    pub udp_rx_payload_bytes: u64,
    pub rtt_conversion_overflow: bool,
}

#[derive(Clone, Copy)]
pub(super) struct Summary {
    first_us: u64,
    last_us: u64,
    samples: u64,
    first: Sample,
    last: Sample,
    minimum_rtt_us: u64,
    maximum_rtt_us: u64,
    minimum_cwnd_bytes: u64,
    maximum_cwnd_bytes: u64,
    invalid: bool,
    overflow: bool,
}

impl Summary {
    pub(super) fn due(value: Option<&Self>, now: u64) -> bool {
        value.is_none_or(|value| {
            now.checked_sub(value.last_us)
                .is_none_or(|elapsed| elapsed >= SAMPLE_INTERVAL_US)
        })
    }

    pub(super) fn sample(value: &mut Option<Self>, now: u64, sample: Sample) {
        let state = value.get_or_insert(Self {
            first_us: now,
            last_us: now,
            samples: 0,
            first: sample,
            last: sample,
            minimum_rtt_us: sample.rtt_us,
            maximum_rtt_us: sample.rtt_us,
            minimum_cwnd_bytes: sample.cwnd_bytes,
            maximum_cwnd_bytes: sample.cwnd_bytes,
            invalid: false,
            overflow: false,
        });
        state.invalid |= now < state.last_us
            || sample.congestion_events < state.last.congestion_events
            || sample.lost_quic_packets < state.last.lost_quic_packets
            || sample.lost_quic_bytes < state.last.lost_quic_bytes
            || sample.sent_quic_packets < state.last.sent_quic_packets
            || sample.udp_tx_datagrams < state.last.udp_tx_datagrams
            || sample.udp_rx_datagrams < state.last.udp_rx_datagrams
            || sample.udp_tx_payload_bytes < state.last.udp_tx_payload_bytes
            || sample.udp_rx_payload_bytes < state.last.udp_rx_payload_bytes;
        state.overflow |= sample.rtt_conversion_overflow;
        state.samples = state.samples.checked_add(1).unwrap_or_else(|| {
            state.overflow = true;
            u64::MAX
        });
        state.last_us = state.last_us.max(now);
        state.last = sample;
        state.minimum_rtt_us = state.minimum_rtt_us.min(sample.rtt_us);
        state.maximum_rtt_us = state.maximum_rtt_us.max(sample.rtt_us);
        state.minimum_cwnd_bytes = state.minimum_cwnd_bytes.min(sample.cwnd_bytes);
        state.maximum_cwnd_bytes = state.maximum_cwnd_bytes.max(sample.cwnd_bytes);
    }

    pub(super) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"definition\":\"sampled public Quinn connection statistics; cumulative connection counters include setup; UDP datagram counts are not QUIC packet counts or application records; UDP payload bytes exclude IP/UDP headers; sampled extrema do not establish time spent congestion-limited or queue occupancy; last sample can precede terminal observation\",\"sampling_interval_us\":{SAMPLE_INTERVAL_US},\"first_observed_us\":{},\"last_observed_us\":{},\"samples\":{},\"minimum_rtt_us\":{},\"maximum_rtt_us\":{},\"minimum_cwnd_bytes\":{},\"maximum_cwnd_bytes\":{},\"invalid\":{},\"overflow\":{},\"received_quic_packets\":null,\"first\":",
            self.first_us,
            self.last_us,
            self.samples,
            self.minimum_rtt_us,
            self.maximum_rtt_us,
            self.minimum_cwnd_bytes,
            self.maximum_cwnd_bytes,
            self.invalid,
            self.overflow
        )?;
        self.first.write(out)?;
        write!(out, ",\"last\":")?;
        self.last.write(out)?;
        write!(out, "}}")
    }
}

impl Sample {
    fn write(self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"rtt_us\":{},\"cwnd_bytes\":{},\"congestion_events\":{},\"lost_quic_packets\":{},\"lost_quic_bytes\":{},\"sent_quic_packets\":{},\"udp_tx_datagrams\":{},\"udp_rx_datagrams\":{},\"udp_tx_payload_bytes\":{},\"udp_rx_payload_bytes\":{}}}",
            self.rtt_us,
            self.cwnd_bytes,
            self.congestion_events,
            self.lost_quic_packets,
            self.lost_quic_bytes,
            self.sent_quic_packets,
            self.udp_tx_datagrams,
            self.udp_rx_datagrams,
            self.udp_tx_payload_bytes,
            self.udp_rx_payload_bytes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Sample {
        Sample {
            rtt_us: 70_000,
            cwnd_bytes: 2816,
            congestion_events: 2,
            lost_quic_packets: 3,
            lost_quic_bytes: 4224,
            sent_quic_packets: 10,
            udp_tx_datagrams: 9,
            udp_rx_datagrams: 8,
            udp_tx_payload_bytes: 10_000,
            udp_rx_payload_bytes: 2000,
            rtt_conversion_overflow: false,
        }
    }
    #[test]
    fn quic_public_stats_sample_cadence_and_counter_regression_are_explicit()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = None;
        assert!(Summary::due(value.as_ref(), 20));
        Summary::sample(&mut value, 20, sample());
        assert!(!Summary::due(value.as_ref(), 100_019));
        assert!(Summary::due(value.as_ref(), 100_020));
        let mut next = sample();
        next.cwnd_bytes = 5632;
        next.rtt_us = 90_000;
        next.udp_rx_datagrams += 4;
        Summary::sample(&mut value, 100_020, next);
        let state = value.as_ref().ok_or("missing diagnostic sample")?;
        assert_eq!(state.samples, 2);
        assert_eq!(state.first.udp_rx_datagrams, 8);
        assert_eq!(state.last.udp_rx_datagrams, 12);
        assert_eq!(state.minimum_cwnd_bytes, 2816);
        assert_eq!(state.maximum_cwnd_bytes, 5632);
        assert!(!state.invalid);
        let mut output = Vec::new();
        state.write(&mut output)?;
        assert!(String::from_utf8(output)?.contains("\"received_quic_packets\":null"));
        // Backward clocks and counters remain visible instead of inventing deltas.
        next.udp_rx_datagrams = 0;
        Summary::sample(&mut value, 100_019, next);
        assert!(value.as_ref().ok_or("missing diagnostic sample")?.invalid);
        Ok(())
    }
}

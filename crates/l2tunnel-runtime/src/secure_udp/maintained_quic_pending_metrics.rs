//! Fixed scalar samples adjacent to an actual failed QUIC DATAGRAM enqueue.
//! Provider locks are separate; this is context, not an atomic cause snapshot.
use std::io::{self, Write};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Sample {
    pub begin_us: u64,
    pub end_us: u64,
    pub required_payload_bytes: Option<usize>,
    pub available_payload_bytes: usize,
    pub configured_send_buffer_bytes: usize,
    pub rtt_us: u64,
    pub cwnd_bytes: u64,
    pub current_mtu_bytes: u16,
    pub congestion_events: u64,
    pub lost_quic_packets: u64,
    pub lost_quic_bytes: u64,
    pub sent_quic_packets: u64,
    pub udp_tx_datagrams: u64,
    pub udp_tx_payload_bytes: u64,
    pub datagram_frames_tx: u64,
    pub invalid: bool,
}

impl Sample {
    fn follows(self, old: Self) -> bool {
        self.begin_us >= old.end_us
            && self.congestion_events >= old.congestion_events
            && self.lost_quic_packets >= old.lost_quic_packets
            && self.lost_quic_bytes >= old.lost_quic_bytes
            && self.sent_quic_packets >= old.sent_quic_packets
            && self.udp_tx_datagrams >= old.udp_tx_datagrams
            && self.udp_tx_payload_bytes >= old.udp_tx_payload_bytes
            && self.datagram_frames_tx >= old.datagram_frames_tx
            && self.configured_send_buffer_bytes == old.configured_send_buffer_bytes
            && self.required_payload_bytes == old.required_payload_bytes
    }
    fn write(self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"begin_us\":{},\"end_us\":{},\"required_payload_bytes\":",
            self.begin_us, self.end_us
        )?;
        match self.required_payload_bytes {
            Some(value) => write!(out, "{value}")?,
            None => write!(out, "null")?,
        }
        write!(
            out,
            ",\"available_payload_bytes\":{},\"configured_send_buffer_bytes\":{},\"rtt_us\":{},\"cwnd_bytes\":{},\"current_mtu_bytes\":{},\"congestion_events\":{},\"lost_quic_packets\":{},\"lost_quic_bytes\":{},\"sent_quic_packets\":{},\"udp_tx_datagrams\":{},\"udp_tx_payload_bytes\":{},\"datagram_frames_tx\":{},\"bytes_in_flight\":null,\"pacing_deadline_us\":null,\"invalid\":{}}}",
            self.available_payload_bytes,
            self.configured_send_buffer_bytes,
            self.rtt_us,
            self.cwnd_bytes,
            self.current_mtu_bytes,
            self.congestion_events,
            self.lost_quic_packets,
            self.lost_quic_bytes,
            self.sent_quic_packets,
            self.udp_tx_datagrams,
            self.udp_tx_payload_bytes,
            self.datagram_frames_tx,
            self.invalid
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Pending {
    polls: u64,
    required_payload_bytes: Option<usize>,
    first_us: Option<u64>,
    latest_us: Option<u64>,
    first: Option<Sample>,
    latest: Option<Sample>,
}
impl Pending {
    pub(super) fn observe(&mut self, now: u64, required: Option<usize>, invalid: &mut bool) {
        if self.first_us.is_some() {
            *invalid |= self.required_payload_bytes != required;
        }
        self.required_payload_bytes = required;
        *invalid |= self.latest_us.is_some_and(|old| now < old);
        super::add(&mut self.polls, 1, invalid);
        self.first_us.get_or_insert(now);
        self.latest_us = Some(self.latest_us.map_or(now, |old| old.max(now)));
    }
    pub(super) fn observed(&self) -> bool {
        self.first_us.is_some()
    }
    pub(super) fn needs_first_sample(&self) -> bool {
        self.first_us.is_some() && self.first.is_none()
    }
    pub(super) fn sample(&mut self, mut value: Sample, invalid: &mut bool) {
        value.required_payload_bytes = self.required_payload_bytes;
        let Some(last_pending) = self.latest_us else {
            *invalid = true;
            return;
        };
        *invalid |= value.invalid
            || value.begin_us < last_pending
            || value.end_us < value.begin_us
            || value.available_payload_bytes > value.configured_send_buffer_bytes
            || self.latest.is_some_and(|old| !value.follows(old));
        self.first.get_or_insert(value);
        self.latest = Some(value);
    }
    pub(super) fn elapsed(&self, end: u64) -> Option<u64> {
        end.checked_sub(self.first_us?)
    }
    pub(super) fn write(self, out: &mut impl Write) -> io::Result<()> {
        write!(out, "{{\"polls\":{},\"first_us\":", self.polls)?;
        super::optional(out, self.first_us)?;
        write!(out, ",\"latest_us\":")?;
        super::optional(out, self.latest_us)?;
        for (name, value) in [("first_sample", self.first), ("latest_sample", self.latest)] {
            write!(out, ",\"{name}\":")?;
            match value {
                Some(value) => value.write(out)?,
                None => write!(out, "null")?,
            }
        }
        write!(out, "}}")
    }
}

//! Bounded QUIC adapter observations, separate from transport authority.
use super::Class;
use crate::buffer_metrics::{
    Class as MetricClass, Extent, Key, Lane, Observer, Occupancy, Reason, Site,
};
use l2tunnel_quic::common::BufferSnapshot;
use std::io::{self, Write};
#[path = "maintained_quic_transport_metrics.rs"]
mod transport;
pub(crate) use transport::Sample as TransportSample;
#[path = "maintained_quic_ticket_metrics.rs"]
pub(crate) mod tickets;

#[derive(Clone, Copy, Default)]
pub(crate) struct Snapshot {
    lanes: [Option<Provider>; 2],
    pub(crate) tickets: tickets::Snapshot,
}

#[derive(Clone, Copy)]
struct Provider {
    samples: u64,
    send_capacity: usize,
    receive_capacity: usize,
    available: usize,
    minimum_available: usize,
    maximum_available: usize,
    invalid: bool,
    overflow: bool,
    transport: Option<transport::Summary>,
}

impl Snapshot {
    pub(crate) fn transport_due(&self, lane: usize, now: u64) -> bool {
        self.lanes
            .get(lane)
            .and_then(Option::as_ref)
            .is_some_and(|value| transport::Summary::due(value.transport.as_ref(), now))
    }
    pub(crate) fn sample_transport(&mut self, lane: usize, now: u64, sample: TransportSample) {
        if let Some(value) = self.lanes.get_mut(lane).and_then(Option::as_mut) {
            transport::Summary::sample(&mut value.transport, now, sample);
        }
    }

    pub(crate) fn sample(&mut self, lane: usize, value: BufferSnapshot) {
        let Some(slot) = self.lanes.get_mut(lane) else {
            return;
        };
        let state = slot.get_or_insert(Provider {
            samples: 0,
            send_capacity: value.outgoing_send_buffer_capacity,
            receive_capacity: value.incoming_receive_buffer_capacity,
            available: value.available_payload_bytes,
            minimum_available: value.available_payload_bytes,
            maximum_available: value.available_payload_bytes,
            invalid: false,
            overflow: false,
            transport: None,
        });
        state.invalid |= value.invalid_slot_observation
            || value.available_payload_bytes > state.send_capacity
            || value.outgoing_send_buffer_capacity != state.send_capacity
            || value.incoming_receive_buffer_capacity != state.receive_capacity;
        state.samples = state.samples.checked_add(1).unwrap_or_else(|| {
            state.overflow = true;
            u64::MAX
        });
        state.available = value.available_payload_bytes;
        state.minimum_available = state.minimum_available.min(value.available_payload_bytes);
        state.maximum_available = state.maximum_available.max(value.available_payload_bytes);
    }

    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"definition\":\"provider available-payload gauge includes private metadata allowance; configured cap minus available is not exact payload or heap occupancy; CarrierSubmission bytes are caller-record bytes in unresolved futures, excluding bootstrap envelopes; completed slots can retain only a result; CarrierAdmission waits include observed scheduling delay\",\"lanes\":["
        )?;
        let mut first = true;
        for (lane, value) in self.lanes.iter().enumerate() {
            let Some(value) = value else {
                continue;
            };
            if !first {
                write!(out, ",")?;
            }
            first = false;
            write!(
                out,
                "{{\"lane\":{lane},\"samples\":{},\"configured_send_buffer_bytes\":{},\"configured_receive_buffer_bytes\":{},\"available_payload_bytes\":{},\"minimum_available_payload_bytes\":{},\"maximum_available_payload_bytes\":{},\"outgoing_used_bytes\":null,\"incoming_used_bytes\":null,\"invalid\":{},\"overflow\":{}",
                value.samples,
                value.send_capacity,
                value.receive_capacity,
                value.available,
                value.minimum_available,
                value.maximum_available,
                value.invalid,
                value.overflow
            )?;
            write!(out, ",\"transport_statistics\":")?;
            if let Some(value) = &value.transport {
                value.write(out)?;
            } else {
                write!(out, "null")?;
            }
            write!(out, "}}")?;
        }
        write!(out, "],\"tickets\":")?;
        self.tickets.write(out)?;
        write!(out, "}}")
    }
}

fn class(value: Class) -> MetricClass {
    match value {
        Class::User => MetricClass::User,
        Class::Control => MetricClass::Management,
    }
}
fn lane(value: usize) -> Lane {
    Lane::at(value)
}
fn key(site: Site, physical_lane: Lane, value: Class) -> Key {
    Key {
        site,
        lane: physical_lane,
        class: class(value),
    }
}

pub(super) fn event(
    metrics: &mut Option<Observer>,
    site: Site,
    physical_lane: Option<usize>,
    value: Class,
    reason: Reason,
    blocked: bool,
) {
    let Some(metrics) = metrics.as_mut().filter(|metrics| !metrics.is_finished()) else {
        return;
    };
    let now = metrics.now();
    let key = key(site, physical_lane.map_or(Lane::Shared, lane), value);
    let _ = if blocked {
        metrics.collector().blocked(key, reason, now)
    } else {
        metrics.collector().progress(key, reason, now)
    };
}

pub(super) fn finish(metrics: &mut Option<Observer>) {
    if let Some(metrics) = metrics.as_mut() {
        metrics.finish_at(metrics.now());
    }
}

pub(super) fn lower(metrics: &mut Option<Observer>, index: usize, snapshot: BufferSnapshot) {
    let Some(metrics) = metrics.as_mut().filter(|metrics| !metrics.is_finished()) else {
        return;
    };
    let now = metrics.now();
    metrics.sample_quic(index, snapshot);
    for (value, slots) in [
        (Class::User, snapshot.user_slots),
        (Class::Control, snapshot.control_slots),
    ] {
        if let Some(used) = slots.used {
            let _ = metrics.collector().sample(
                key(Site::QuicSend, lane(index), value),
                now,
                Occupancy {
                    bytes: None,
                    items: Some(Extent {
                        used: used as u64,
                        capacity: Some(slots.capacity as u64),
                    }),
                },
            );
        }
    }
}

pub(super) fn output(
    metrics: &mut Option<Observer>,
    value: Class,
    occupied: bool,
    pending_bytes: usize,
    accepted: bool,
    capacity: usize,
) {
    let Some(metrics) = metrics.as_mut().filter(|metrics| !metrics.is_finished()) else {
        return;
    };
    let now = metrics.now();
    let _ = metrics.collector().sample(
        key(Site::CarrierSubmission, Lane::Shared, value),
        now,
        Occupancy {
            bytes: Some(Extent {
                used: pending_bytes as u64,
                capacity: Some(capacity as u64),
            }),
            items: Some(Extent {
                used: u64::from(occupied),
                capacity: Some(1),
            }),
        },
    );
    let _ = metrics.collector().sample(
        key(Site::CarrierReceipt, Lane::Shared, value),
        now,
        Occupancy {
            bytes: None,
            items: Some(Extent {
                used: u64::from(accepted),
                capacity: Some(1),
            }),
        },
    );
}

pub(super) fn input(
    metrics: &mut Option<Observer>,
    physical_lane: Option<usize>,
    bytes: Option<usize>,
    capacity: usize,
) {
    let Some(metrics) = metrics.as_mut().filter(|metrics| !metrics.is_finished()) else {
        return;
    };
    let now = metrics.now();
    let _ = metrics.collector().sample(
        Key {
            site: Site::CarrierInput,
            lane: physical_lane.map_or(Lane::Shared, lane),
            class: MetricClass::Shared,
        },
        now,
        Occupancy {
            bytes: Some(Extent {
                used: bytes.unwrap_or(0) as u64,
                capacity: Some(capacity as u64),
            }),
            items: Some(Extent {
                used: u64::from(bytes.is_some()),
                capacity: Some(1),
            }),
        },
    );
}

/// Separate ticket lifetime can outlast the generic collector's first-error stop.
pub(super) fn ticket_event(
    metrics: &mut Option<Observer>,
    timestamp: Option<tokio::time::Instant>,
    event: impl FnOnce(&mut tickets::Snapshot, u64, Option<u64>),
) {
    let Some(metrics) = metrics
        .as_mut()
        .filter(|metrics| metrics.has_quic_tickets())
    else {
        return;
    };
    let now = metrics.now();
    let converted = timestamp.and_then(|at| metrics.elapsed_at(at));
    if let Some(state) = metrics.quic_tickets() {
        if timestamp.is_some() && converted.is_none() {
            state.invalid_clock();
        }
        event(state, now, converted);
    }
}

/// Capture public context only at first actual Pending or the existing sample cadence.
/// Separate provider locks make begin/end a bracket, never an atomic denial reason.
pub(super) fn ticket_pending(
    metrics: &mut Option<Observer>,
    carrier: &l2tunnel_quic::common::Carrier,
    id: tickets::Identity,
    physical_lane: usize,
    required_payload_bytes: Option<usize>,
) {
    let Some(metrics) = metrics
        .as_mut()
        .filter(|metrics| metrics.has_quic_tickets())
    else {
        return;
    };
    let now = metrics.now();
    let first = metrics
        .quic_tickets()
        .is_some_and(|state| state.pending(id, required_payload_bytes, now));
    let cadence_due = metrics.quic_transport_due(physical_lane, now);
    if !first && !cadence_due {
        return;
    }
    pending_provider_sample(metrics, carrier, physical_lane, cadence_due.then_some(now));
}

/// Reuse one existing per-lane sample for all still-unresolved local tickets.
/// A shared sample neither starts another wait nor reports a new failed enqueue.
pub(super) fn pending_provider_sample(
    metrics: &mut Observer,
    carrier: &l2tunnel_quic::common::Carrier,
    physical_lane: usize,
    cadence_at: Option<u64>,
) {
    let begin_us = metrics.now();
    let buffers = carrier.buffer_snapshot();
    let stats = carrier.transport_statistics();
    let end_us = metrics.now();
    let micros = stats.path.rtt.as_micros();
    let rtt_us = micros.min(u128::from(u64::MAX)) as u64;
    let rtt_conversion_overflow = micros > u128::from(u64::MAX);
    // Share the existing per-lane cadence so observe_buffers cannot duplicate
    // this provider query in the same turn. This does not arm a timer or wake.
    if let Some(cadence_at) = cadence_at {
        metrics.sample_quic_transport(
            physical_lane,
            cadence_at,
            TransportSample {
                rtt_us,
                rtt_conversion_overflow,
                cwnd_bytes: stats.path.cwnd,
                congestion_events: stats.path.congestion_events,
                lost_quic_packets: stats.path.lost_packets,
                lost_quic_bytes: stats.path.lost_bytes,
                sent_quic_packets: stats.path.sent_packets,
                udp_tx_datagrams: stats.udp_tx.datagrams,
                udp_rx_datagrams: stats.udp_rx.datagrams,
                udp_tx_payload_bytes: stats.udp_tx.bytes,
                udp_rx_payload_bytes: stats.udp_rx.bytes,
            },
        );
    }
    if let Some(state) = metrics.quic_tickets() {
        state.pending_lane_sample(
            physical_lane,
            tickets::PendingSample {
                begin_us,
                end_us,
                required_payload_bytes: None,
                available_payload_bytes: buffers.available_payload_bytes,
                configured_send_buffer_bytes: buffers.outgoing_send_buffer_capacity,
                rtt_us,
                cwnd_bytes: stats.path.cwnd,
                current_mtu_bytes: stats.path.current_mtu,
                congestion_events: stats.path.congestion_events,
                lost_quic_packets: stats.path.lost_packets,
                lost_quic_bytes: stats.path.lost_bytes,
                sent_quic_packets: stats.path.sent_packets,
                udp_tx_datagrams: stats.udp_tx.datagrams,
                udp_tx_payload_bytes: stats.udp_tx.bytes,
                datagram_frames_tx: stats.frame_tx.datagram,
                invalid: rtt_conversion_overflow || buffers.invalid_slot_observation,
            },
        );
    }
}

//! Bounded QUIC adapter observations, separate from transport authority.
use super::Class;
use crate::buffer_metrics::{
    Class as MetricClass, Extent, Key, Lane, Observer, Occupancy, Reason, Site,
};
use l2tunnel_quic::common::BufferSnapshot;
use std::io::{self, Write};

#[derive(Clone, Copy, Default)]
pub(crate) struct Snapshot {
    lanes: [Option<Provider>; 2],
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
}

impl Snapshot {
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
                "{{\"lane\":{lane},\"samples\":{},\"configured_send_buffer_bytes\":{},\"configured_receive_buffer_bytes\":{},\"available_payload_bytes\":{},\"minimum_available_payload_bytes\":{},\"maximum_available_payload_bytes\":{},\"outgoing_used_bytes\":null,\"incoming_used_bytes\":null,\"invalid\":{},\"overflow\":{}}}",
                value.samples,
                value.send_capacity,
                value.receive_capacity,
                value.available,
                value.minimum_available,
                value.maximum_available,
                value.invalid,
                value.overflow
            )?;
        }
        write!(out, "]}}")
    }
}

fn class(value: Class) -> MetricClass {
    match value {
        Class::User => MetricClass::User,
        Class::Control => MetricClass::Management,
    }
}
fn lane(value: usize) -> Lane {
    if value == 0 {
        Lane::First
    } else {
        Lane::Second
    }
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

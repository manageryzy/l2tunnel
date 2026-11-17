//! Exact bounded raw-owner projection; cumulative refusals do not fabricate intervals.
use super::raw_carrier_io as adapter;
use crate::buffer_metrics::{Class, Extent, Key, Lane, Observer, Occupancy, Site};
use l2tunnel_raw_io::handoff::pairing::packet as raw;
use std::io::{self, Write};
use tokio::time::Instant;

#[derive(Clone, Copy)]
pub(crate) struct Snapshot {
    raw: adapter::BufferSnapshot,
    observed_at_us: u64,
    wrapper_captured_at_us: Option<u64>,
    carrier_captured_at_us: Option<u64>,
}

pub(in crate::secure_udp) fn observe(
    snapshot: adapter::BufferSnapshot,
    observer: &mut Observer,
    now: Instant,
) {
    if observer.is_finished() {
        return;
    }
    let Some(at) = observer.elapsed_at(now) else {
        return;
    };
    for (index, lane) in snapshot.carrier.lanes.iter().enumerate() {
        let Some(lane) = lane else {
            continue;
        };
        let key_lane = if index == 0 {
            Lane::First
        } else {
            Lane::Second
        };
        // Only gauges are projected into the generic collector. A terminal
        // count cannot reconstruct refusal times, successes or interval union.
        for (site, occupancy) in [
            (
                Site::RawSend,
                Occupancy {
                    bytes: Some(Extent {
                        used: lane.pending_ip_bytes as u64,
                        capacity: None,
                    }),
                    items: Some(Extent {
                        used: u64::from(lane.pending_ip_bytes != 0),
                        capacity: Some(1),
                    }),
                },
            ),
            (
                Site::RawCredit,
                Occupancy {
                    bytes: lane.send_debt_bytes.map(|used| Extent {
                        used,
                        capacity: lane.peer_horizon_bytes,
                    }),
                    items: None,
                },
            ),
        ] {
            let _ = observer.collector().sample(
                Key {
                    site,
                    lane: key_lane,
                    class: Class::Shared,
                },
                at,
                occupancy,
            );
        }
    }
    observer.retain_raw(Snapshot {
        raw: snapshot,
        observed_at_us: at,
        wrapper_captured_at_us: observer.elapsed_at(snapshot.captured_at),
        carrier_captured_at_us: observer.elapsed_at(snapshot.carrier.captured_at),
    });
}

impl Snapshot {
    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"observed_at_us\":{},\"wrapper_captured_at_us\":",
            self.observed_at_us
        )?;
        optional(out, self.wrapper_captured_at_us)?;
        write!(out, ",\"carrier_captured_at_us\":")?;
        optional(out, self.carrier_captured_at_us)?;
        write!(
            out,
            ",\"capture_stage\":\"last_sample_before_common_terminal_settlement\",\"terminal_definition\":\"raw carrier released-state flag; a stopped Common loop can still have terminal false\",\"terminal\":{},\"unavailable_lanes\":{},\"timing\":\"local quota/pacing and prepare refusals remain untimed; optional PacketIo timing uses synchronous actual inner-send edges, never periodic count reconstruction; lane intervals overlap and must not be summed; candidate ages are residence, not blocked intervals\",\"counter_saturation\":\"u64::MAX is a saturated lower bound\",\"lanes\":[",
            self.raw.carrier.terminal, self.raw.carrier.unavailable_lanes
        )?;
        for (index, lane) in self.raw.carrier.lanes.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            if let Some(lane) = lane {
                write_lane(out, index, lane)?;
            } else {
                write!(out, "null")?;
            }
        }
        write!(
            out,
            "],\"wrapper\":{{\"control_capacity_bytes\":{},\"input_capacity_bytes\":{},\"prepared\":",
            self.raw.control_capacity_bytes, self.raw.input_capacity_bytes
        )?;
        if let Some(value) = self.raw.prepared {
            write!(
                out,
                "{{\"lane\":{},\"kind\":\"{:?}\",\"record_bytes\":{}}}",
                value.lane, value.kind, value.record_bytes
            )?;
        } else {
            write!(out, "null")?;
        }
        write!(out, ",\"user\":")?;
        pending(out, self.raw.user)?;
        write!(out, ",\"control\":")?;
        pending(out, self.raw.control)?;
        write!(out, ",\"input\":")?;
        if let Some(value) = self.raw.input {
            write!(
                out,
                "{{\"record_bytes\":{},\"age_micros\":{},\"final_kind\":",
                value.record_bytes, value.age_micros
            )?;
            optional_kind(out, value.final_kind)?;
            write!(out, "}}")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, ",\"prepare\":[")?;
        for (index, value) in self.raw.prepare.iter().enumerate() {
            if index != 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"kind\":\"{}\",\"ready\":{},\"local_custody_refusals\":{},\"carrier_refusals\":{},\"last_refusal\":",
                kind_name(index),
                value.ready,
                value.local_custody_refusals,
                value.carrier_refusals
            )?;
            match value.last_refusal {
                Some(adapter::PrepareRefusal::LocalCustody {
                    lane,
                    prepared,
                    user,
                    control,
                }) => {
                    write!(out, "{{\"reason\":\"local_custody\",\"lane\":")?;
                    optional(out, lane.map(u64::from))?;
                    write!(
                        out,
                        ",\"prepared\":{prepared},\"user\":{user},\"control\":{control}}}"
                    )?;
                }
                Some(adapter::PrepareRefusal::Carrier { lane, reason }) => {
                    write!(out, "{{\"reason\":\"carrier\",\"lane\":{lane},\"detail\":")?;
                    refusal(out, reason)?;
                    write!(out, "}}")?;
                }
                None => write!(out, "null")?,
            }
            write!(out, "}}")?;
        }
        write!(out, "]}}}}")
    }
}

fn write_lane(
    out: &mut impl Write,
    index: usize,
    value: &raw::LaneBufferSnapshot,
) -> io::Result<()> {
    write!(
        out,
        "{{\"lane\":{index},\"candidate_capacity_packets\":{},\"upper_bulk_shared_slot\":{},\"bootstrap_records_outstanding\":{},\"bootstrap_control_queued\":{},\"total_gate_rejected_packets\":{},\"selected_kind\":",
        value.candidate_capacity_packets,
        value.upper_bulk_shared_slot,
        value.bootstrap_records_outstanding,
        value.bootstrap_control_queued,
        value.total_gate_rejected_packets
    )?;
    optional_kind(out, value.selected_kind)?;
    for (name, count) in [
        ("selected_age_micros", value.selected_age_micros),
        ("local_horizon_bytes", value.local_horizon_bytes),
        ("peer_horizon_bytes", value.peer_horizon_bytes),
        ("send_debt_bytes", value.send_debt_bytes),
        ("retired_bytes", value.retired_bytes),
    ] {
        write!(out, ",\"{name}\":")?;
        optional(out, count)?;
    }
    write!(
        out,
        ",\"prepared_payload_bytes\":{},\"pending_ip_bytes\":{},\"packet_io_pending\":{},\"tracked\":{},\"completed\":{},\"candidate_classes\":{{",
        value.prepared_payload_bytes,
        value.pending_ip_bytes,
        value.packet_io_pending,
        value.tracked,
        value.completed
    )?;
    for (index, (name, candidate)) in [
        ("carrier_control", value.carrier_control),
        ("upper_control", value.upper_control),
        ("bulk_data_feedback", value.bulk),
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(out, "\"{name}\":")?;
        write_candidate(out, candidate)?;
    }
    write!(out, "}},\"prepare\":[")?;
    for (index, prepare) in value.prepare.iter().enumerate() {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"kind\":\"{}\",\"ready\":{},\"local_custody_refusals\":{},\"peer_horizon_refusals\":{},\"control_retry_refusals\":{},\"last_refusal\":",
            kind_name(index),
            prepare.ready,
            prepare.local_custody_refusals,
            prepare.peer_horizon_refusals,
            prepare.control_retry_refusals
        )?;
        if let Some(reason) = prepare.last_refusal {
            refusal(out, reason)?;
        } else {
            write!(out, "null")?;
        }
        write!(out, "}}")?;
    }
    let io = value.send_io;
    write!(
        out,
        "],\"send_io\":{{\"turn_budget_refusals\":{},\"pacing_refusals\":{},\"packet_io_attempts\":{},\"would_block_observations\":{},\"would_block_episodes\":{},\"resumed_episodes\":{},\"cancelled_episodes\":{},\"blocked\":{},\"duration_us\":null,\"timing\":",
        io.turn_budget_refusals,
        io.pacing_refusals,
        io.packet_io_attempts,
        io.would_block_observations,
        io.would_block_episodes,
        io.resumed_episodes,
        io.cancelled_episodes,
        io.blocked
    )?;
    if let Some(timing) = value.send_timing {
        write_send_timing(out, timing)?;
    } else {
        write!(out, "null")?;
    }
    write!(
        out,
        ",\"diagnostic_heap_bytes\":{}}}}}",
        value.send_timing_capacity_bytes
    )
}

fn write_send_timing(out: &mut impl Write, value: raw::SendTimingSnapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"observed_micros\":{},\"would_block_observations\":{},\"completed\":{{\"episodes\":{},\"micros\":{}}},\"cancelled\":{{\"episodes\":{},\"micros\":{}}},\"terminal\":{{\"episodes\":{},\"micros\":{}}},\"open_micros\":",
        value.observed_micros,
        value.would_block_observations,
        value.completed.episodes,
        value.completed.micros,
        value.cancelled.episodes,
        value.cancelled.micros,
        value.terminal.episodes,
        value.terminal.micros
    )?;
    optional(out, value.open_micros)?;
    write!(
        out,
        ",\"maximum_micros\":{},\"left_censored_episodes\":{},\"durations_are_lower_bounds\":{},\"stopped\":{},\"invalid_clock\":{},\"counter_overflow\":{}}}",
        value.maximum_micros,
        value.left_censored_episodes,
        value.durations_are_lower_bounds,
        value.stopped,
        value.invalid_clock,
        value.counter_overflow
    )
}

fn write_candidate(out: &mut impl Write, value: raw::CandidateBufferSnapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"capacity_packets\":{},\"capacity_payload_bytes\":{},\"queued_packets\":{},\"queued_payload_bytes\":{},\"oldest_age_micros\":",
        value.capacity_packets,
        value.capacity_payload_bytes,
        value.queued_packets,
        value.queued_payload_bytes
    )?;
    optional(out, value.oldest_age_micros)?;
    write!(
        out,
        ",\"high_water_packets\":{},\"high_water_payload_bytes\":{}",
        value.counters.high_water_packets, value.counters.high_water_payload_bytes
    )?;
    for (name, count) in [
        ("admitted", value.counters.admitted),
        ("capacity_refused", value.counters.capacity_refused),
        ("preflight_rejected", value.counters.preflight_rejected),
        ("verifier_rejected", value.counters.verifier_rejected),
        ("accepted", value.counters.accepted),
    ] {
        write!(
            out,
            ",\"{name}\":{{\"packets\":{},\"payload_bytes\":{}}}",
            count.packets, count.payload_bytes
        )?;
    }
    write!(out, "}}")
}
fn refusal(out: &mut impl Write, value: raw::FinalPrepareBlocked) -> io::Result<()> {
    match value {
        raw::FinalPrepareBlocked::LocalCustody {
            pending,
            packet_io_pending,
            prepared,
            tracked,
            completed,
        } => write!(
            out,
            "{{\"reason\":\"local_custody\",\"pending\":{pending},\"packet_io_pending\":{packet_io_pending},\"prepared\":{prepared},\"tracked\":{tracked},\"completed\":{completed}}}"
        ),
        raw::FinalPrepareBlocked::PeerHorizon {
            requested_end,
            allowed_end,
            allocated,
            peer_retired,
            horizon_bytes,
            reserved_bytes,
        } => write!(
            out,
            "{{\"reason\":\"peer_horizon\",\"requested_end\":{requested_end},\"allowed_end\":{allowed_end},\"allocated\":{allocated},\"peer_retired\":{peer_retired},\"horizon_bytes\":{horizon_bytes},\"reserved_bytes\":{reserved_bytes}}}"
        ),
        raw::FinalPrepareBlocked::ControlRetry => write!(out, "{{\"reason\":\"control_retry\"}}"),
    }
}
fn pending(out: &mut impl Write, value: Option<adapter::PendingBufferSnapshot>) -> io::Result<()> {
    if let Some(value) = value {
        write!(
            out,
            "{{\"lane\":{},\"record_bytes\":{},\"charged_bytes\":{},\"bootstrap\":{},\"token_retained\":{},\"receipt_retained\":{},\"deadline_remaining_micros\":{}}}",
            value.lane,
            value.record_bytes,
            value.charged_bytes,
            value.bootstrap,
            value.token_retained,
            value.receipt_retained,
            value.deadline_remaining_micros
        )
    } else {
        write!(out, "null")
    }
}
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    if let Some(value) = value {
        write!(out, "{value}")
    } else {
        write!(out, "null")
    }
}
fn optional_kind(out: &mut impl Write, value: Option<raw::compact::FinalKind>) -> io::Result<()> {
    if let Some(value) = value {
        write!(out, "\"{value:?}\"")
    } else {
        write!(out, "null")
    }
}
fn kind_name(index: usize) -> &'static str {
    ["Data", "Feedback", "Control", "CarrierControl"][index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_packet_io_timing_json_preserves_censored_episodes_and_unknown_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let timing = raw::SendTimingSnapshot {
            observed_micros: 90,
            would_block_observations: 4,
            completed: raw::SendTimingTotal {
                episodes: 1,
                micros: 10,
            },
            cancelled: raw::SendTimingTotal {
                episodes: 1,
                micros: 20,
            },
            terminal: raw::SendTimingTotal {
                episodes: 1,
                micros: 30,
            },
            maximum_micros: 30,
            left_censored_episodes: 1,
            durations_are_lower_bounds: true,
            stopped: true,
            ..raw::SendTimingSnapshot::default()
        };
        let mut bytes = Vec::new();
        write_send_timing(&mut bytes, timing)?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(value["completed"]["micros"], 10);
        assert_eq!(value["cancelled"]["micros"], 20);
        assert_eq!(value["terminal"]["micros"], 30);
        assert_eq!(value["left_censored_episodes"], 1);
        assert_eq!(value["durations_are_lower_bounds"], true);
        assert_eq!(value["stopped"], true);
        assert!(value["open_micros"].is_null());
        Ok(())
    }

    #[test]
    fn raw_json_keeps_lane_class_refusal_and_untimed_terminal_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let reason = raw::FinalPrepareBlocked::PeerHorizon {
            requested_end: 1005,
            allowed_end: 1000,
            allocated: 995,
            peer_retired: 100,
            horizon_bytes: 1000,
            reserved_bytes: 100,
        };
        let candidate = raw::CandidateBufferSnapshot {
            capacity_packets: 4,
            capacity_payload_bytes: 5840,
            queued_packets: 2,
            queued_payload_bytes: 100,
            oldest_age_micros: Some(99),
            counters: raw::CandidateCounters {
                capacity_refused: raw::PacketCount {
                    packets: 7,
                    payload_bytes: 350,
                },
                high_water_packets: 3,
                high_water_payload_bytes: 150,
                ..raw::CandidateCounters::default()
            },
        };
        let lane = raw::LaneBufferSnapshot {
            carrier_control: candidate,
            upper_control: raw::CandidateBufferSnapshot {
                queued_packets: 1,
                ..candidate
            },
            bulk: raw::CandidateBufferSnapshot {
                capacity_packets: 60,
                ..candidate
            },
            candidate_capacity_packets: 68,
            upper_bulk_shared_slot: false,
            bootstrap_records_outstanding: 1,
            bootstrap_control_queued: 0,
            total_gate_rejected_packets: 9,
            selected_kind: Some(raw::compact::FinalKind::Control),
            selected_age_micros: Some(50),
            local_horizon_bytes: Some(1000),
            peer_horizon_bytes: Some(1000),
            send_debt_bytes: Some(895),
            retired_bytes: Some(100),
            prepared_payload_bytes: 0,
            pending_ip_bytes: 61,
            packet_io_pending: true,
            tracked: true,
            completed: false,
            prepare: [raw::PrepareSnapshot {
                peer_horizon_refusals: 2,
                last_refusal: Some(reason),
                ..raw::PrepareSnapshot::default()
            }; 4],
            send_timing: None,
            send_timing_capacity_bytes: 0,
            send_io: raw::SendIoSnapshot {
                would_block_observations: 10,
                would_block_episodes: 2,
                resumed_episodes: 1,
                blocked: true,
                ..raw::SendIoSnapshot::default()
            },
        };
        let snapshot = Snapshot {
            observed_at_us: 1000,
            wrapper_captured_at_us: Some(1000),
            carrier_captured_at_us: Some(900),
            raw: adapter::BufferSnapshot {
                captured_at: now,
                carrier: raw::BufferSnapshot {
                    captured_at: now,
                    terminal: true,
                    lanes: [Some(lane), None],
                    unavailable_lanes: 2,
                },
                prepared: Some(adapter::PreparedBufferSnapshot {
                    lane: 0,
                    kind: raw::compact::FinalKind::Data,
                    record_bytes: 21,
                }),
                user: Some(adapter::PendingBufferSnapshot {
                    lane: 0,
                    record_bytes: 21,
                    charged_bytes: 61,
                    bootstrap: false,
                    token_retained: true,
                    receipt_retained: false,
                    deadline: now,
                    deadline_remaining_micros: 0,
                }),
                control: None,
                input: Some(adapter::InputBufferSnapshot {
                    record_bytes: 50,
                    age_micros: 50,
                    final_kind: Some(raw::compact::FinalKind::Control),
                }),
                control_capacity_bytes: 1460,
                input_capacity_bytes: 1460,
                prepare: [adapter::PrepareObservations {
                    carrier_refusals: 2,
                    last_refusal: Some(adapter::PrepareRefusal::Carrier { lane: 0, reason }),
                    ..adapter::PrepareObservations::default()
                }; 4],
            },
        };
        let mut bytes = Vec::new();
        snapshot.write(&mut bytes)?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(json["observed_at_us"], 1000);
        assert_eq!(json["carrier_captured_at_us"], 900);
        assert_eq!(json["terminal"], true);
        assert_eq!(json["unavailable_lanes"], 2);
        assert!(json["lanes"][1].is_null());
        let lane = &json["lanes"][0];
        assert_eq!(
            lane["candidate_classes"]["carrier_control"]["queued_packets"],
            2
        );
        assert_eq!(
            lane["candidate_classes"]["upper_control"]["queued_packets"],
            1
        );
        assert_eq!(
            lane["candidate_classes"]["bulk_data_feedback"]["capacity_packets"],
            60
        );
        assert_eq!(
            lane["candidate_classes"]["upper_control"]["capacity_refused"]["packets"],
            7
        );
        assert_eq!(lane["prepare"][0]["last_refusal"]["reason"], "peer_horizon");
        assert_eq!(lane["prepare"][0]["last_refusal"]["requested_end"], 1005);
        assert_eq!(lane["send_io"]["would_block_episodes"], 2);
        assert!(lane["send_io"]["duration_us"].is_null());
        assert_eq!(json["wrapper"]["user"]["charged_bytes"], 61);
        assert!(json["wrapper"]["control"].is_null());
        assert_eq!(
            json["wrapper"]["prepare"][0]["last_refusal"]["detail"]["reason"],
            "peer_horizon"
        );
        Ok(())
    }
}

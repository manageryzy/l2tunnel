//! Terminal serialization of exact pure Rolling/Research refusal intervals.
use l2tunnel::rolling_records::waits::{Operation, Snapshot, Terminal, Totals};
use std::io::{self, Write};
#[path = "rolling_ingress_metrics.rs"]
mod ingress;
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(v) => write!(out, "{v}"),
        None => write!(out, "null"),
    }
}
fn operation(out: &mut impl Write, value: Operation) -> io::Result<()> {
    write!(
        out,
        "{{\"id\":{},\"bytes\":{},\"original_deadline_us\":",
        value.id, value.bytes
    )?;
    optional(out, value.deadline.map(|v| v.0))?;
    write!(
        out,
        ",\"packets\":{},\"wire_bytes\":{},\"copies\":{}}}",
        value.packets, value.wire_bytes, value.copies
    )
}
fn totals(out: &mut impl Write, t: Totals) -> io::Result<()> {
    write!(
        out,
        "{{\"completed_episodes\":{},\"completed_us\":{},\"maximum_completed_us\":{},\"censored_episodes\":{},\"censored_us\":{},\"maximum_censored_us\":{}}}",
        t.completed_episodes,
        t.completed_us,
        t.maximum_completed_us,
        t.censored_episodes,
        t.censored_us,
        t.maximum_censored_us
    )
}
pub(super) fn write(out: &mut impl Write, s: &Snapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"definition\":\"actual refusal to same-operation ownership progress; includes scheduling delay; no durations combined across sites; reason intervals can overlap; sampled occupancy is separate\",\"coverage\":\"sealed source recovery admission, decoded source record handoff, ready feedback output budget and optional actual receive data-head Busy intervals; work Pending and feedback-build dependencies remain unavailable\",\"instance\":{},\"session_hex\":\"",
        s.instance
    )?;
    for byte in s.send_scope.session {
        write!(out, "{byte:02x}")?;
    }
    write!(
        out,
        "\",\"epoch\":{},\"stream\":{},\"send_direction\":{},\"observed_at_us\":{},\"terminal_at_us\":",
        s.send_scope.epoch, s.send_scope.stream, s.send_scope.direction, s.observed_at.0
    )?;
    optional(out, s.terminal.map(|v| v.0.0))?;
    write!(out, ",\"terminal_stage\":")?;
    match s.terminal.map(|v| v.1) {
        Some(Terminal::OwnerFailure) => write!(out, "\"owner_failure\"")?,
        Some(Terminal::MetricStop) => write!(out, "\"pre_settlement_metric_stop\"")?,
        Some(Terminal::DriverDrop) => write!(out, "\"driver_drop\"")?,
        None => write!(out, "null")?,
    }
    write!(
        out,
        ",\"clock_regression\":{},\"identity_mismatch\":{},\"counter_overflow\":{},\"sites\":[",
        s.clock_regression, s.identity_mismatch, s.overflow
    )?;
    for (index, (name, row)) in ["source_admission", "decoded_handoff", "feedback_budget"]
        .into_iter()
        .zip(s.sites.iter())
        .enumerate()
    {
        if index != 0 {
            write!(out, ",")?;
        }
        let direction = if index == 0 {
            s.send_scope.direction
        } else {
            s.send_scope.direction ^ 1
        };
        let cap = if index == 0 {
            "codec_stage"
        } else if index == 1 {
            "decoder_handoff_cohort"
        } else {
            "immutable_feedback_output"
        };
        write!(
            out,
            "{{\"site\":\"{name}\",\"direction\":{direction},\"deadline_owner\":\"{cap}\",\"union\":"
        )?;
        totals(out, row.union)?;
        write!(out, ",\"reasons\":[")?;
        for (i, name) in [
            "recovery_busy",
            "recovery_capacity",
            "record_busy",
            "record_capacity",
            "record_window",
            "packet_budget",
            "wire_byte_budget",
        ]
        .into_iter()
        .enumerate()
        {
            if i != 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"reason\":\"{name}\",\"refusals\":{},\"totals\":",
                row.refusals[i]
            )?;
            totals(out, row.reasons[i])?;
            write!(out, ",\"pending_since_us\":")?;
            optional(
                out,
                row.pending.and_then(|p| p.reasons_since[i]).map(|v| v.0),
            )?;
            write!(out, "}}")?;
        }
        write!(out, "],\"pending\":")?;
        if let Some(p) = row.pending {
            write!(out, "{{\"operation\":")?;
            operation(out, p.operation)?;
            write!(
                out,
                ",\"since_us\":{},\"last_refusal_us\":{},\"open_us\":",
                p.since.0, p.last_refusal.0
            )?;
            optional(out, s.observed_at.0.checked_sub(p.since.0))?;
            write!(out, "}}")?;
        } else {
            write!(out, "null")?;
        }
        write!(out, ",\"last_resolved\":")?;
        if let Some(r) = row.last_resolved {
            write!(out, "{{\"operation\":")?;
            operation(out, r.operation)?;
            write!(
                out,
                ",\"since_us\":{},\"at_us\":{},\"censored\":{}}}",
                r.since.0, r.at.0, r.censored
            )?;
        } else {
            write!(out, "null")?;
        }
        write!(out, "}}")?;
    }
    write!(out, "],\"ingress_admission\":")?;
    ingress::write(
        out,
        s.ingress_admission.as_ref(),
        s.send_scope.direction ^ 1,
        s.observed_at.0,
    )?;
    write!(out, "}}")
}

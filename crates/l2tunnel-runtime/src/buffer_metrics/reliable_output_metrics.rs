//! Exact Block FEC outgoing budget observations, never a carrier wait estimate.
use l2tunnel_reliable::diagnostics::{Operation, Snapshot, Totals};
use std::io::{self, Write};
use std::time::Duration;
fn optional(out: &mut impl Write, value: Option<Duration>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{}", value.as_micros()),
        None => write!(out, "null"),
    }
}
fn operation(out: &mut impl Write, value: Operation) -> io::Result<()> {
    write!(
        out,
        "{{\"generation\":{},\"symbol\":{},\"bytes\":{}}}",
        value.generation, value.symbol, value.bytes
    )
}
fn totals(out: &mut impl Write, value: Totals) -> io::Result<()> {
    write!(
        out,
        "{{\"completed_episodes\":{},\"completed_us\":{},\"maximum_completed_us\":{},\"censored_episodes\":{},\"censored_us\":{},\"maximum_censored_us\":{}}}",
        value.completed_episodes,
        value.completed.as_micros(),
        value.maximum_completed.as_micros(),
        value.censored_episodes,
        value.censored.as_micros(),
        value.maximum_censored.as_micros()
    )
}
pub(super) fn write(out: &mut impl Write, value: &Snapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"definition\":\"actual sealed queue-head budget refusal to emission; includes scheduling delay; does not mean physical acceptance; per-reason durations overlap and must not be summed; capacity refusals are counts only\",\"coverage\":\"shared Aligned/Packed Block output only; Direct ARQ has capacity counts but no sealed-output wait; builder hold, restored-source waits, missing-equation dependencies and physical receipt latency unavailable\",\"scope\":\"endpoint-shared\",\"epoch\":{},\"send_direction\":{},\"sealed_output_present\":{},\"observed_at_us\":{},\"terminal_at_us\":",
        value.epoch,
        value.send_direction,
        value.sealed_output_present,
        value.observed_at.as_micros()
    )?;
    optional(out, value.terminal_at)?;
    write!(
        out,
        ",\"clock_regression\":{},\"identity_mismatch\":{},\"counter_overflow\":{},\"union\":",
        value.clock_regression, value.identity_mismatch, value.overflow
    )?;
    totals(out, value.union)?;
    write!(out, ",\"reasons\":[")?;
    for (index, name) in ["packet_budget", "wire_byte_budget"]
        .into_iter()
        .enumerate()
    {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"reason\":\"{name}\",\"refusals\":{},\"totals\":",
            value.refusals[index]
        )?;
        totals(out, value.reasons[index])?;
        write!(out, ",\"pending_since_us\":")?;
        optional(out, value.pending.and_then(|p| p.reasons_since[index]))?;
        write!(out, "}}")?;
    }
    write!(out, "],\"pending\":")?;
    if let Some(pending) = value.pending {
        write!(out, "{{\"operation\":")?;
        operation(out, pending.operation)?;
        write!(
            out,
            ",\"since_us\":{},\"last_refusal_us\":{},\"open_us\":",
            pending.since.as_micros(),
            pending.last_refusal.as_micros()
        )?;
        optional(out, value.observed_at.checked_sub(pending.since))?;
        write!(out, "}}")?;
    } else {
        write!(out, "null")?;
    }
    write!(out, ",\"last_resolved\":")?;
    if let Some(last) = value.last_resolved {
        write!(out, "{{\"operation\":")?;
        operation(out, last.operation)?;
        write!(
            out,
            ",\"since_us\":{},\"at_us\":{},\"censored\":{}}}",
            last.since.as_micros(),
            last.at.as_micros(),
            last.censored
        )?;
    } else {
        write!(out, "null")?;
    }
    write!(out, ",\"capacity_refusals\":[")?;
    for (index, name) in [
        "fec_symbol_slots",
        "fec_generation_slots",
        "fec_logical_reservation",
        "restored_packet_slots",
        "restored_byte_budget",
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"reason\":\"{name}\",\"refusals\":{}}}",
            value.capacity_refusals[index]
        )?;
    }
    write!(out, "]}}")
}

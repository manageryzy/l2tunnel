//! Per-restored-source refusal to same-source ARQ admission; not an owner time union.
use l2tunnel_reliable::diagnostics::restored::{Open, Pending, Resolved, Snapshot};
use std::io::{self, Write};
fn open(out: &mut impl Write, value: Open) -> io::Result<()> {
    write!(
        out,
        "{{\"episodes\":{},\"sum_us\":{},\"maximum_us\":{}}}",
        value.episodes,
        value.elapsed.as_micros(),
        value.maximum.as_micros()
    )
}
fn pending(out: &mut impl Write, value: Option<Pending>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    write!(
        out,
        "{{\"source\":{},\"bytes\":{},\"recovered\":{},\"since_us\":{},\"last_refusal_us\":{},\"reasons_since_us\":[",
        value.operation.source,
        value.operation.bytes,
        value.operation.recovered,
        value.since.as_micros(),
        value.last_refusal.as_micros()
    )?;
    super::optional(out, value.reasons_since[0])?;
    write!(out, ",")?;
    super::optional(out, value.reasons_since[1])?;
    write!(out, "]}}")
}
fn resolved(out: &mut impl Write, value: Option<Resolved>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    write!(out, "{{\"pending\":")?;
    pending(out, Some(value.pending))?;
    write!(
        out,
        ",\"at_us\":{},\"censored\":{}}}",
        value.at.as_micros(),
        value.censored
    )
}
pub(super) fn write(out: &mut impl Write, value: &Snapshot, direction: u8) -> io::Result<()> {
    write!(
        out,
        "{{\"schema\":1,\"scope\":\"endpoint-shared-receive\",\"receive_direction\":{direction},\"definition\":\"actual retained restored-source ARQ refusal until successful admission of that same source or fresh terminal censor; source durations overlap and are not an owner blocked-time union; reason intervals run from first actual refusal to that progress, not continuous cause truth\",\"coverage\":\"one prepaid cell per configured restored slot; full source identity checked before progress; only latest and extrema retained in report, no event history; successful admission is not native delivery; missing source/prefix dependency, eligible feedback delay/budget and FEC missing equations unavailable\",\"cells\":{},\"restored_bytes_capacity\":{},\"observed_at_us\":{},\"terminal_at_us\":",
        value.cells,
        value.restored_bytes_capacity,
        value.observed_at.as_micros()
    )?;
    super::optional(out, value.terminal_at)?;
    write!(
        out,
        ",\"omitted_refusals\":{},\"identity_mismatch\":{},\"clock_regression\":{},\"counter_overflow\":{},\"terminal_unavailable\":{},\"sources\":",
        value.omitted_refusals,
        value.identity_mismatch,
        value.clock_regression,
        value.overflow,
        value.terminal_unavailable
    )?;
    super::totals(out, value.sources)?;
    write!(out, ",\"open\":")?;
    open(out, value.open)?;
    write!(out, ",\"reasons\":[")?;
    for (index, reason) in ["arq_capacity", "arq_sequence_window"]
        .into_iter()
        .enumerate()
    {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"reason\":\"{reason}\",\"refusals\":{},\"totals\":",
            value.refusals[index]
        )?;
        super::totals(out, value.reasons[index])?;
        write!(out, ",\"open\":")?;
        open(out, value.reasons_open[index])?;
        write!(out, "}}")?;
    }
    write!(out, "],\"maximum_open\":")?;
    pending(out, value.maximum_open)?;
    write!(out, ",\"last_completed\":")?;
    resolved(out, value.last_completed)?;
    write!(out, ",\"maximum_completed\":")?;
    resolved(out, value.maximum_completed)?;
    write!(out, ",\"maximum_censored\":")?;
    resolved(out, value.maximum_censored)?;
    write!(out, "}}")
}

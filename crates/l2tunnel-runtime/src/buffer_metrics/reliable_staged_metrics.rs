//! Identity attachments to staged wait episodes, not another wait-duration union.
use super::optional;
use l2tunnel_recovery::AdmissionSnapshot;
use l2tunnel_reliable::diagnostics::staged::{
    Pending, Resolved, Retirement, RetirementKind, Snapshot,
};
use std::io::{self, Write};

fn gate(out: &mut impl Write, value: AdmissionSnapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"next_source\":{},\"span_base\":",
        value.next_source.0
    )?;
    match value.span_base {
        Some(source) => write!(out, "{}", source.0)?,
        None => write!(out, "null")?,
    }
    write!(
        out,
        ",\"records\":{},\"records_capacity\":{},\"bytes\":{},\"bytes_capacity\":{},\"proposed_bytes\":{},\"resulting_bytes\":{},\"records_full\":{},\"bytes_full\":{},\"sequence_full\":{},\"oldest\":",
        value.records,
        value.records_capacity,
        value.bytes,
        value.bytes_capacity,
        value.proposed_bytes,
        value.resulting_bytes,
        value.records_full,
        value.bytes_full,
        value.sequence_full
    )?;
    if let Some(oldest) = value.oldest {
        write!(
            out,
            "{{\"source\":{},\"attempts\":{},\"transmission\":{},\"acknowledged\":{},\"retry_at_us\":",
            oldest.source.0, oldest.attempts, oldest.transmission, oldest.acknowledged
        )?;
        optional(out, oldest.retry_at)?;
        write!(out, "}}")?;
    } else {
        write!(out, "null")?;
    }
    write!(out, "}}")
}
fn retirement(out: &mut impl Write, value: Option<Retirement>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    let kind = match value.kind {
        RetirementKind::Input => "input",
        RetirementKind::Physical => "physical",
    };
    write!(
        out,
        "{{\"serial\":{},\"observed_us\":{},\"accepted_us\":",
        value.serial,
        value.observed.as_micros()
    )?;
    optional(out, value.accepted)?;
    write!(
        out,
        ",\"kind\":\"{kind}\",\"records\":{},\"bytes\":{},\"operation_succeeded\":{}}}",
        value.records, value.bytes, value.operation_succeeded
    )
}
fn pending(out: &mut impl Write, value: Pending) -> io::Result<()> {
    write!(
        out,
        "{{\"source\":{},\"bytes\":{},\"since_us\":{},\"last_refusal_us\":{},\"retirement_before\":{},\"unit\":",
        value.source,
        value.bytes,
        value.since.as_micros(),
        value.last_refusal.as_micros(),
        value.retirement_before
    )?;
    if let Some(unit) = value.unit {
        write!(
            out,
            "{{\"channel\":{},\"record\":{},\"native_record\":{},\"offset\":{},\"context\":{}}}",
            unit.channel, unit.record, unit.native_record, unit.offset, unit.context
        )?;
    } else {
        write!(out, "null")?;
    }
    write!(out, ",\"native\":")?;
    if let Some(native) = value.native {
        write!(
            out,
            "{{\"flow\":{},\"received_us\":{},\"queued_us\":{},\"deadline_us\":",
            native.flow,
            native.received.as_micros(),
            native.queued.as_micros()
        )?;
        optional(out, native.deadline)?;
        write!(out, "}}")?;
    } else {
        write!(out, "null")?;
    }
    write!(out, ",\"first_gate\":")?;
    gate(out, value.first)?;
    write!(out, ",\"last_gate\":")?;
    gate(out, value.last)?;
    write!(out, "}}")
}
fn resolved(out: &mut impl Write, value: Option<Resolved>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    write!(out, "{{\"pending\":")?;
    pending(out, value.pending)?;
    write!(
        out,
        ",\"at_us\":{},\"censored\":{},\"latest_retirement\":",
        value.at.as_micros(),
        value.censored
    )?;
    retirement(out, value.retirement)?;
    write!(out, "}}")
}
pub(super) fn write(out: &mut impl Write, value: &Snapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"schema\":1,\"definition\":\"identity and actual predicates attached to existing staged_admission episodes, not additional timing totals; maximum and terminal identities are distinct; retirement is a witnessed retention decrease, not proof it alone enabled this source\",\"coverage\":\"shared SelectiveRepeat source only; Aligned unit and successful Pipeline native provenance when available; Packed multi-unit and independent Compact provenance unavailable; later refused Pipeline head remains a separate original\",\"invalid\":{},\"terminal_at_us\":",
        value.invalid
    )?;
    optional(out, value.terminal)?;
    write!(out, ",\"pending\":")?;
    match value.pending {
        Some(value) => pending(out, value)?,
        None => write!(out, "null")?,
    }
    write!(out, ",\"last_resolved\":")?;
    resolved(out, value.last_resolved)?;
    write!(out, ",\"maximum_completed\":")?;
    resolved(out, value.maximum_completed)?;
    write!(out, ",\"maximum_censored\":")?;
    resolved(out, value.maximum_censored)?;
    write!(out, ",\"last_retirement\":")?;
    retirement(out, value.last_retirement)?;
    write!(out, "}}")
}

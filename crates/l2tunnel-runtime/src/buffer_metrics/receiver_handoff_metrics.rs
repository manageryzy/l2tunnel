//! Bounded terminal JSON export; this does not poll or change receiver ownership.
use l2tunnel_aligned::receiver_handoff::{Pending, Reason, Release, Resolved, Snapshot, Terminal};
use std::io::{self, Write};

fn reason(value: Reason) -> &'static str {
    match value {
        Reason::Capacity => "capacity",
        Reason::RecordWindow => "record_window",
    }
}
fn pending(out: &mut impl Write, value: Option<Pending>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    write!(
        out,
        "{{\"source\":{},\"bytes\":{},\"original_deadline_us\":{},\"since_us\":{},\"last_refusal_us\":{},\"first_reason\":\"{}\",\"last_reason\":\"{}\"}}",
        value.identity.source,
        value.identity.bytes,
        value.identity.deadline.as_micros(),
        value.since.as_micros(),
        value.last_refusal.as_micros(),
        reason(value.first_reason),
        reason(value.last_reason)
    )
}
fn resolved(out: &mut impl Write, value: Option<Resolved>) -> io::Result<()> {
    let Some(value) = value else {
        return write!(out, "null");
    };
    write!(out, "{{\"pending\":")?;
    pending(out, Some(value.pending))?;
    write!(out, ",\"at_us\":{},\"release\":", value.at.as_micros())?;
    match value.release {
        Some(release) => write!(
            out,
            "\"{}\"",
            match release {
                Release::Admitted => "admitted",
                Release::AlreadyObserved => "already_observed",
                Release::PackedBatch => "packed_batch",
            }
        )?,
        None => write!(out, "null")?,
    }
    write!(out, "}}")
}
pub(super) fn write(out: &mut impl Write, value: &Snapshot) -> io::Result<()> {
    write!(
        out,
        "{{\"schema\":1,\"scope\":\"endpoint-shared-receive\",\"definition\":\"actual Capacity/RecordWindow outer refusal through release of the same immutable recovery source; includes scheduling delay, not continuous cause truth or native delivery; one live cell; reasons are counts, not additive durations; microseconds truncate submicrosecond time\",\"epoch\":{},\"receive_direction\":{},\"packed\":{},\"cells\":1,\"inner_unit_identity\":null,\"missing_context_wait\":null,\"native_consumer_wait\":null,\"observed_at_us\":{},\"terminal_at_us\":",
        value.epoch,
        value.receive_direction,
        value.packed,
        value.observed_at.as_micros()
    )?;
    super::duration(out, value.terminal_at)?;
    write!(out, ",\"terminal\":")?;
    match value.terminal {
        Some(Terminal::OwnerFailure) => write!(out, "\"owner_failure\"")?,
        Some(Terminal::MetricStop) => write!(out, "\"metric_stop\"")?,
        None => write!(out, "null")?,
    }
    let total = value.totals;
    write!(
        out,
        ",\"terminal_unavailable\":{},\"clock_regression\":{},\"identity_mismatch\":{},\"counter_overflow\":{},\"refusals\":[{{\"reason\":\"capacity\",\"count\":{}}},{{\"reason\":\"record_window\",\"count\":{}}}],\"totals\":{{\"completed_episodes\":{},\"completed_us\":{},\"maximum_completed_us\":{},\"censored_episodes\":{},\"censored_us\":{},\"maximum_censored_us\":{}}},\"pending\":",
        value.terminal_unavailable,
        value.clock_regression,
        value.identity_mismatch,
        value.overflow,
        value.refusals[0],
        value.refusals[1],
        total.completed_episodes,
        total.completed.as_micros(),
        total.maximum_completed.as_micros(),
        total.censored_episodes,
        total.censored.as_micros(),
        total.maximum_censored.as_micros()
    )?;
    pending(out, value.pending)?;
    write!(out, ",\"last_resolved\":")?;
    resolved(out, value.last_resolved)?;
    write!(out, ",\"maximum_completed\":")?;
    resolved(out, value.maximum_completed)?;
    write!(out, ",\"maximum_censored\":")?;
    resolved(out, value.maximum_censored)?;
    write!(out, "}}")
}

#[cfg(test)]
mod tests {
    use super::super::{Identity as EpochIdentity, ProtocolBuffers};
    use super::*;
    use l2tunnel_aligned::receiver_handoff::{Identity, Totals};
    use l2tunnel_management::Role;
    use std::time::Duration;

    #[test]
    fn receiver_handoff_provider_retains_exact_scope_and_requires_fresh_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let make = |at| Snapshot {
            epoch: 7,
            receive_direction: 1,
            packed: false,
            observed_at: Duration::from_micros(at),
            terminal_at: None,
            terminal: None,
            terminal_unavailable: false,
            refusals: [2, 0],
            totals: Totals::default(),
            pending: Some(Pending {
                identity: Identity {
                    source: 900,
                    bytes: 83,
                    deadline: Duration::from_micros(200),
                },
                since: Duration::from_micros(10),
                last_refusal: Duration::from_micros(15),
                first_reason: Reason::Capacity,
                last_reason: Reason::Capacity,
            }),
            last_resolved: None,
            maximum_completed: None,
            maximum_censored: None,
            clock_regression: false,
            identity_mismatch: false,
            overflow: false,
        };
        let mut provider = ProtocolBuffers::new(1, Role::Client)?;
        let baseline = provider.heap_bytes();
        provider.configure_receiver_handoff()?;
        let allocated = provider.heap_bytes();
        assert_eq!(allocated - baseline, 2 * std::mem::size_of::<Snapshot>());
        let epoch = EpochIdentity {
            epoch: 7,
            configuration: [6; 32],
        };
        assert!(provider.begin(20, [Some(epoch), None]));
        provider.sample_receiver_handoff(epoch, make(20));
        provider.finish_receiver_handoff(30);
        let stale = provider.epochs[0]
            .receiver_handoff
            .first()
            .ok_or("retained sample")?;
        assert!(stale.terminal_unavailable && stale.pending.is_some());
        assert_eq!(stale.terminal_at, None);
        assert!(provider.begin(30, [Some(epoch), None]));
        provider.sample_receiver_handoff(epoch, make(30));
        provider.finish_receiver_handoff(30);
        let mut output = Vec::new();
        provider.write(&mut output)?;
        let value: serde_json::Value = serde_json::from_slice(&output)?;
        let row = &value["epochs"][0]["receiver_handoff"];
        assert_eq!(row["epoch"], 7);
        assert_eq!(row["receive_direction"], 1);
        assert_eq!(row["totals"]["censored_us"], 20);
        assert_eq!(row["maximum_censored"]["pending"]["source"], 900);
        assert_eq!(
            row["maximum_censored"]["pending"]["original_deadline_us"],
            200
        );
        assert!(row["inner_unit_identity"].is_null() && row["pending"].is_null());
        assert_eq!(provider.heap_bytes(), allocated);
        assert!(make(30).pending.is_some()); // Censoring never mutates the actual protocol owner.
        let wrong = EpochIdentity {
            epoch: 8,
            configuration: [7; 32],
        };
        assert!(provider.begin(40, [Some(wrong), None]));
        provider.sample_receiver_handoff(wrong, make(40));
        assert_eq!(provider.identity_errors, 1);
        assert!(provider.epochs[1].receiver_handoff.is_empty());
        Ok(())
    }
}

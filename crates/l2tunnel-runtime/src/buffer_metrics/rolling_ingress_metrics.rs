//! Serialization of one actual receiving data-head refusal population.
use super::{Write, optional};
use l2tunnel::fec::rolling::expiry::{DecoderJob, Identity};
use l2tunnel::rolling_records::waits::ingress::{Input, Kind, Outcome, Pending, Snapshot};
use std::io;
fn distribution(
    out: &mut impl Write,
    value: &l2tunnel::rolling_records::waits::ingress::residence::Distribution,
) -> io::Result<()> {
    write!(
        out,
        "{{\"count\":{},\"sum_us\":{},\"maximum_us\":{},\"at_least_100ms\":{},\"mean_us\":",
        value.count, value.sum_us, value.maximum_us, value.at_least_100ms
    )?;
    if value.count == 0 {
        write!(out, "null")?;
    } else {
        write!(out, "{}", value.sum_us as f64 / value.count as f64)?;
    }
    write!(out, ",\"p99_upper_us\":")?;
    optional(out, value.p99_upper_us())?;
    write!(out, ",\"buckets\":[")?;
    for (index, count) in value.buckets.iter().enumerate() {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(out, "{count}")?;
    }
    write!(out, "]}}")
}
fn input(out: &mut impl Write, v: Input) -> io::Result<()> {
    write!(out, "{{\"records_number\":")?;
    optional(out, v.records_number)?;
    let kind = match v.kind {
        Kind::Source => "source",
        Kind::Repair => "repair",
    };
    write!(
        out,
        ",\"received_us\":{},\"original_deadline_us\":{},\"bytes\":{},\"kind\":\"{kind}\"}}",
        v.received.0, v.deadline.0, v.bytes
    )
}
fn job(out: &mut impl Write, v: Option<DecoderJob>) -> io::Result<()> {
    let Some(v) = v else {
        return write!(out, "null");
    };
    write!(out, "{{\"identity\":")?;
    match v.identity {
        Identity::Sources { first, end } => write!(
            out,
            "{{\"kind\":\"source\",\"first\":{first},\"end\":{end}}}"
        )?,
        Identity::Repair { id, support } => {
            write!(out, "{{\"kind\":\"repair\",\"id\":{},\"support\":", id.0)?;
            if let Some((first, end)) = support {
                write!(out, "[{first},{end}]")?;
            } else {
                write!(out, "null")?;
            }
            write!(out, "}}")?;
        }
        Identity::Near8(id) => write!(out, "{{\"kind\":\"near8\",\"group\":{}}}", id.0)?,
        Identity::Feedback(id) => write!(out, "{{\"kind\":\"unexpected_feedback\",\"id\":{id}}}")?,
    }
    write!(
        out,
        ",\"received_us\":{},\"admitted_us\":{},\"original_deadline_us\":{}}}",
        v.received.0, v.admitted.0, v.deadline.0
    )
}
fn pending(out: &mut impl Write, v: Pending) -> io::Result<()> {
    write!(out, "{{\"serial\":{},\"input\":", v.serial)?;
    input(out, v.input)?;
    write!(
        out,
        ",\"since_us\":{},\"last_refusal_us\":{},\"first_blocker\":",
        v.since.0, v.last_refusal.0
    )?;
    job(out, v.first_blocker)?;
    write!(out, ",\"latest_blocker\":")?;
    job(out, v.latest_blocker)?;
    write!(out, "}}")
}
pub(super) fn write(
    out: &mut impl Write,
    v: Option<&Snapshot>,
    direction: u8,
    observed: u64,
) -> io::Result<()> {
    let Some(v) = v else {
        return write!(out, "null");
    };
    write!(
        out,
        "{{\"schema\":1,\"receive_direction\":{direction},\"definition\":\"actual immutable data FIFO-head Busy to same-head successful removal or fresh terminal censor; includes scheduling; original arrival residence is separate; outcomes are not all decoder admission; blocker is not the queued input; no work Pending or CPU attribution\",\"next_head\":{},\"refusals\":{},\"omitted_refusals\":{},\"blocker_unavailable\":{},\"terminal_unavailable\":{},\"terminal_at_us\":",
        v.next_head, v.refusals, v.omitted_refusals, v.blocker_unavailable, v.terminal_unavailable
    )?;
    optional(out, v.terminal_at.map(|t| t.0))?;
    let independent = v.independent_population;
    write!(
        out,
        ",\"independent_commits\":{},\"independent_head_wait\":{{\"episodes\":{},\"sum_us\":{},\"maximum_us\":{}}}",
        v.residence.independent_commits,
        independent.episodes,
        independent.elapsed_us,
        independent.maximum_us
    )?;
    write!(out, ",\"populations\":[")?;
    for (i, name) in ["staged", "duplicate", "stale", "censored"]
        .into_iter()
        .enumerate()
    {
        if i != 0 {
            write!(out, ",")?;
        }
        let row = v.populations[i];
        write!(
            out,
            "{{\"outcome\":\"{name}\",\"episodes\":{},\"sum_us\":{},\"maximum_us\":{},\"completions\":",
            row.episodes, row.elapsed_us, row.maximum_us
        )?;
        optional(out, v.completions.get(i).copied())?;
        write!(out, ",\"without_refusal\":")?;
        optional(out, v.without_refusal.get(i).copied())?;
        write!(out, "}}")?;
    }
    write!(out, "],\"pending\":")?;
    if let Some(p) = v.pending {
        pending(out, p)?;
    } else {
        write!(out, "null")?;
    }
    write!(out, ",\"open_us\":")?;
    optional(
        out,
        if v.terminal_unavailable {
            None
        } else {
            v.pending.and_then(|p| observed.checked_sub(p.since.0))
        },
    )?;
    write!(out, ",\"last_resolved\":")?;
    if let Some(r) = v.last_resolved {
        write!(out, "{{\"pending\":")?;
        pending(out, r.pending)?;
        write!(out, ",\"at_us\":{},\"outcome\":", r.at.0)?;
        match r.outcome {
            Some(Outcome::Staged) => write!(out, "\"staged\"")?,
            Some(Outcome::Duplicate) => write!(out, "\"duplicate\"")?,
            Some(Outcome::Stale) => write!(out, "\"stale\"")?,
            Some(Outcome::Independent) => write!(out, "\"independent\"")?,
            None => write!(out, "\"censored\"")?,
        }
        write!(out, ",\"admitted_job\":")?;
        job(out, r.admitted_job)?;
        write!(out, "}}")?;
    } else {
        write!(out, "null")?;
    }
    write!(
        out,
        ",\"queue_residence\":{{\"schema\":1,\"definition\":\"original authenticated arrival to successful data removal on both paths; immediate means FIFO bypass, not zero age; includes Staged/Duplicate/Stale outcomes, not all decoder job admission; retained ages are current or terminal-censored, never completed; histogram p99 is an upper bound, not exact or additive; feedback excluded\",\"all\":"
    )?;
    distribution(out, &v.residence.all)?;
    write!(out, ",\"immediate\":")?;
    distribution(out, &v.residence.immediate)?;
    write!(out, ",\"queued\":")?;
    distribution(out, &v.residence.queued)?;
    write!(
        out,
        ",\"immediate_outcomes\":{:?},\"queued_outcomes\":{:?},\"retained_at_us\":",
        v.residence.immediate_outcomes, v.residence.queued_outcomes
    )?;
    optional(out, v.residence.retained_at.map(|at| at.0))?;
    write!(
        out,
        ",\"retained_population\":\"{}\",\"retained_ages\":",
        if v.terminal_unavailable {
            "unavailable"
        } else if v.terminal_at.is_some() {
            "censored"
        } else {
            "open_age_snapshot"
        }
    )?;
    if v.terminal_unavailable {
        write!(out, "null")?;
    } else if let Some(ages) = &v.residence.retained_ages {
        distribution(out, ages)?;
    } else {
        write!(out, "null")?;
    }
    write!(out, "}}}}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel::record_engine::Tick;
    use l2tunnel::rolling_records::waits::ingress::{Population, Resolved};
    #[test]
    fn actual_ingress_provider_serializes_blocker_and_new_job_separately()
    -> Result<(), Box<dyn std::error::Error>> {
        let blocker = DecoderJob {
            identity: Identity::Sources { first: 0, end: 1 },
            received: l2tunnel::fec::rolling::Tick(1),
            admitted: l2tunnel::fec::rolling::Tick(10),
            deadline: l2tunnel::fec::rolling::Tick(1000),
            phase: l2tunnel::fec::rolling::expiry::DecoderPhase::Clear(1),
        };
        let admitted = DecoderJob {
            identity: Identity::Sources { first: 1, end: 2 },
            received: l2tunnel::fec::rolling::Tick(2),
            admitted: l2tunnel::fec::rolling::Tick(20),
            deadline: l2tunnel::fec::rolling::Tick(900),
            ..blocker
        };
        let pending = Pending {
            serial: 2,
            input: Input {
                records_number: Some(72),
                received: Tick(2),
                deadline: Tick(900),
                bytes: 64,
                kind: Kind::Source,
            },
            since: Tick(11),
            last_refusal: Tick(12),
            first_blocker: Some(blocker),
            latest_blocker: Some(blocker),
        };
        let mut value = Snapshot {
            next_head: 3,
            refusals: 2,
            completions: [2, 0, 0],
            without_refusal: [1, 0, 0],
            last_resolved: Some(Resolved {
                pending,
                at: Tick(20),
                outcome: Some(Outcome::Staged),
                admitted_job: Some(admitted),
            }),
            ..Snapshot::default()
        };
        value.populations[0] = Population {
            episodes: 1,
            elapsed_us: 9,
            maximum_us: 9,
        };
        let mut buckets = [0; 32];
        buckets[4] = 1; // 9 us.
        buckets[5] = 1; // 18 us.
        let residence = l2tunnel::rolling_records::waits::ingress::residence::Distribution {
            count: 2,
            sum_us: 27,
            maximum_us: 18,
            at_least_100ms: 0,
            buckets,
        };
        value.residence.all = residence;
        value.residence.queued = residence;
        value.residence.queued_outcomes = [2, 0, 0];
        value.residence.retained_ages = Some(Default::default());
        value.residence.retained_at = Some(Tick(100));
        let mut output = Vec::new();
        write(&mut output, Some(&value), 1, 100)?;
        let parsed: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(
            parsed["last_resolved"]["pending"]["first_blocker"]["identity"]["first"],
            0
        );
        assert_eq!(
            parsed["last_resolved"]["admitted_job"]["identity"]["first"],
            1
        );
        assert_eq!(parsed["populations"][0]["without_refusal"], 1);
        assert_eq!(
            parsed["populations"][3]["completions"],
            serde_json::Value::Null
        );
        assert_eq!(parsed["open_us"], serde_json::Value::Null);
        assert_eq!(parsed["queue_residence"]["queued"]["mean_us"], 13.5);
        assert_eq!(parsed["queue_residence"]["queued"]["p99_upper_us"], 31);
        assert_eq!(parsed["queue_residence"]["retained_ages"]["count"], 0);
        assert_eq!(
            parsed["queue_residence"]["retained_ages"]["mean_us"],
            serde_json::Value::Null
        );
        value.terminal_unavailable = true;
        output.clear();
        write(&mut output, Some(&value), 1, 100)?;
        let stale: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(
            stale["queue_residence"]["retained_population"],
            "unavailable"
        );
        assert_eq!(
            stale["queue_residence"]["retained_ages"],
            serde_json::Value::Null
        );
        output.clear();
        write(&mut output, None, 1, 100)?;
        assert_eq!(output, b"null");
        Ok(())
    }
}

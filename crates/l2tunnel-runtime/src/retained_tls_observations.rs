//! Actual stream ownership and incomplete-frame dependencies, never idle reads.
use super::*;

/// A retained output cannot interleave bytes into another active frame. This
/// episode ends when its original class is selected, before any write progress;
/// socket/TLS Pending is measured independently and may overlap other classes.
pub(super) fn writer_dependency(
    lane: &Lane,
    index: usize,
    outputs: &[Output; 2],
    metrics: &mut Option<Observer>,
) {
    if metrics.is_none() {
        return;
    }
    for class in [Class::User, Class::Control] {
        let key = lane_key(Site::TlsWrite, index, metric_class(class));
        if lane.active.is_some_and(|active| active != class)
            && outputs[class.index()]
                .pending
                .as_ref()
                .is_some_and(|pending| pending.lane == index && pending.receipt.is_none())
        {
            metric_blocked(metrics, key, Reason::Dependency);
        } else {
            metric_resumed(metrics, key, Reason::Dependency);
        }
    }
}

/// One terminal observation before stream owners are cleared. The reported
/// stage is the actual failing call; expired candidates are not rewritten as a
/// unique root cause. Observation time follows the check, and no I/O is polled.
pub(super) fn trace_failure(adapter: &Adapter, kind: io::ErrorKind, site: &'static str) {
    if std::env::var_os("L2TUNNEL_TRACE_FAILURE").is_none() {
        return;
    }
    let now = Instant::now();
    let _ = write_failure(adapter, kind, site, now, &mut io::stderr().lock());
}

fn write_failure(
    adapter: &Adapter,
    kind: io::ErrorKind,
    site: &'static str,
    now: Instant,
    output: &mut impl io::Write,
) -> io::Result<()> {
    let overdue = |deadline: Instant| {
        now.checked_duration_since(deadline)
            .map(|duration| duration.as_micros())
    };
    writeln!(
        output,
        "Retained TLS terminal: role={:?} site={site} kind={kind:?} record_timeout_us={} next_deadline_overdue_us={:?}",
        adapter.info.role,
        adapter.plan.limits.record_timeout.as_micros(),
        adapter.next_deadline().and_then(overdue),
    )?;
    for class in [Class::User, Class::Control] {
        if let Some(pending) = adapter.output[class.index()].pending.as_ref() {
            writeln!(
                output,
                "Retained TLS output: class={class:?} serial={} lane={} framed_bytes={} written_bytes={} receipt={} operation_overdue_us={:?} caller_overdue_us={:?}",
                pending.serial,
                pending.lane,
                pending.length,
                pending.offset,
                pending.receipt.is_some(),
                overdue(pending.operation_deadline),
                overdue(pending.deadline),
            )?;
        }
    }
    for (index, lane) in adapter.lanes.iter().enumerate() {
        writeln!(
            output,
            "Retained TLS lane: lane={index} active={:?} prefix_bytes={} body_bytes={} expected_body_bytes={:?} input_ready={} input_overdue_us={:?}",
            lane.active,
            lane.input.prefix_used,
            lane.input.body_used,
            lane.input.length,
            lane.input.ready.is_some(),
            lane.input.deadline.and_then(overdue),
        )?;
    }
    Ok(())
}

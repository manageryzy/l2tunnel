//! Facts derived from the selected descriptor, not a declaration of equivalence.
use l2tunnel::record_configuration::{Descriptor, Profile};
use l2tunnel_recovery::CompactRecovery;
use serde_json::{Value, json};

/// Project the symmetric independent CompactARQ selection. Other policies are
/// deliberately unqualified; callers must never infer the profile from a name.
pub fn actual(descriptor: &Descriptor) -> Value {
    let Profile::PerConnectionCompact { forward, reverse } = descriptor.profile() else {
        return Value::Null;
    };
    if forward != reverse {
        return Value::Null;
    }
    let arq = forward.compact.recovery.arq();
    // KCP-like is an explicit separate policy, not Python CompactARQ parity.
    if matches!(arq.recovery(), CompactRecovery::KcpLike(_)) {
        return Value::Null;
    }
    let bounds = arq.bounds();
    if bounds.send_records != bounds.receive_records
        || bounds.send_bytes != bounds.receive_bytes
        || bounds.send_records.checked_mul(bounds.max_source_bytes) != Some(bounds.send_bytes)
    {
        return Value::Null;
    }
    let timing = arq.timing();
    let (Ok(feedback), Ok(rtt)) = (
        u64::try_from(timing.feedback_interval.as_micros()),
        u64::try_from(timing.nominal_rtt.as_micros()),
    ) else {
        return Value::Null;
    };
    if std::time::Duration::from_micros(feedback) != timing.feedback_interval
        || std::time::Duration::from_micros(rtt) != timing.nominal_rtt
    {
        return Value::Null;
    }
    json!({
        "recovery": match arq.recovery() {
            CompactRecovery::Guarded => "compact_arq_guarded",
            CompactRecovery::FirstFlight => "compact_arq_first_flight",
            CompactRecovery::BoundedGap { .. } => "compact_arq_bounded_gap",
            CompactRecovery::KcpLike(_) => "kcp_like",
        },
        "topology":"per_connection", "owners_per_direction":forward.owners,
        "source_window_per_owner":bounds.send_records,
        "feedback_interval_us":feedback, "feedback_packets":timing.feedback_packets,
        "reverse_ack_path":if forward.unreliable.is_some() {"lossy_unrecovered"} else {"recovered"},
        "nominal_rtt_us":rtt,
    })
}

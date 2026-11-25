//! Bounded local setup failure projection; never a source of protocol authority.
#![cfg(target_os = "linux")]

use crate::service;
use l2tunnel_runtime::secure_udp::diagnostics;
use serde_json::{Value, json};
use std::io;

/// Emit one actual failed completion through the existing bounded logger.
pub(super) fn failed(snapshot: service::SetupObservation, sink: &mut super::output::Sink) {
    if let Some(value) = project(snapshot) {
        sink.emit(value);
        sink.flush_turn();
    } else {
        sink.projection_error();
    }
}

fn project(snapshot: service::SetupObservation) -> Option<Value> {
    if snapshot.outcome != service::SetupOutcome::Failed {
        return None;
    }
    let failure = snapshot.failure?;
    let bootstrap = snapshot
        .runtime
        .and_then(|runtime| runtime.bootstrap)
        .map(|stats| {
            let mut value = json!({
                "received_datagrams": stats.received_datagrams,
                "ignored_datagrams": stats.ignored_datagrams,
                "emitted_datagrams": stats.emitted_datagrams,
                "emitted_udp_bytes": stats.emitted_udp_bytes,
                "socket_sent_datagrams": stats.socket_sent_datagrams,
                "socket_sent_udp_bytes": stats.socket_sent_udp_bytes,
                "socket_drops": stats.socket_drops,
                "socket_receive_errors": stats.socket_receive_errors,
                "noise_flights": stats.noise_flights,
                "noise_duplicates": stats.noise_duplicates,
                "gate_retries": stats.gate_retries,
                "bootstrap_fresh": stats.bootstrap_fresh,
                "bootstrap_replays": stats.bootstrap_replays,
            });
            if stats.maintained_accepted_records != 0 || stats.maintained_accepted_record_bytes != 0
            {
                value["maintained_accepted_records"] = json!(stats.maintained_accepted_records);
                value["maintained_accepted_record_bytes"] =
                    json!(stats.maintained_accepted_record_bytes);
            }
            value
        });
    let control = snapshot
        .runtime
        .and_then(|runtime| runtime.control)
        .map(|stats| {
            json!({
                "transmitted_packets": stats.transmitted_packets,
                "transmitted_ip_bytes": stats.transmitted_ip_bytes,
                "received_packets": stats.received_packets,
                "replay_packets": stats.replay_packets,
                "send_bytes": stats.send_bytes,
                "receive_bytes": stats.receive_bytes,
            })
        });
    let server_gate = snapshot
        .runtime
        .and_then(|runtime| runtime.server_gate)
        .map(|stats| {
            json!({
                "validated_request_bytes": stats.validated_request_bytes,
                "response_bytes": stats.response_bytes,
                "retained_sessions": stats.retained_sessions,
            })
        });
    Some(json!({
        "event": "secure_udp_setup_failed",
        "schema": 1,
        "operation": snapshot.operation.value(),
        "stage": stage(snapshot.stage),
        "outcome": "failed",
        "kind": kind(failure.kind),
        "reason": reason(failure.reason),
        "elapsed_micros": snapshot.elapsed_micros,
        "original_timeout_micros": snapshot.original_timeout_micros,
        "bootstrap": bootstrap,
        "control": control,
        "server_gate_cumulative": server_gate,
        "member_attempts": snapshot.runtime.and_then(|runtime| runtime.member_attempts),
    }))
}

fn stage(stage: service::SetupStage) -> &'static str {
    use service::SetupStage;
    match stage {
        SetupStage::Accepted => "accepted",
        SetupStage::SocketBind => "socket_bind",
        SetupStage::SocketConnect => "socket_connect",
        SetupStage::AdmissionOwner => "admission_owner",
        SetupStage::Configuration => "configuration",
        SetupStage::Admission => "admission",
        SetupStage::Noise => "noise",
        SetupStage::Membership => "membership",
        SetupStage::Attachment => "attachment",
        SetupStage::DriverReadiness => "driver_readiness",
        SetupStage::ReadyPublication => "ready_publication",
    }
}

fn reason(reason: service::SetupFailureReason) -> &'static str {
    use service::SetupFailureReason;
    match reason {
        SetupFailureReason::Runtime(reason) => runtime_reason(reason),
        SetupFailureReason::OriginalDeadline => "original_deadline",
        SetupFailureReason::LocalIo => "local_io",
        SetupFailureReason::ReadinessEnded => "readiness_ended",
        SetupFailureReason::Unknown => "unknown",
    }
}

fn runtime_reason(reason: diagnostics::Reason) -> &'static str {
    use diagnostics::Reason;
    match reason {
        Reason::OriginalDeadline => "original_deadline",
        Reason::BootstrapDeadline => "bootstrap_deadline",
        Reason::MembershipDeadline => "membership_deadline",
        Reason::AdmissionAttempts => "admission_attempts",
        Reason::BootstrapAttempts => "bootstrap_attempts",
        Reason::JoiningAttempts => "joining_attempts",
        Reason::Configuration => "configuration",
        Reason::Entropy => "entropy",
        Reason::Authentication => "authentication",
        Reason::Protocol => "protocol",
        Reason::Cover => "cover",
        Reason::LocalIo => "local_io",
        Reason::Crypto => "crypto",
        Reason::Capacity => "capacity",
        Reason::CounterExhausted => "counter_exhausted",
        Reason::Clock => "clock",
        Reason::LiveTuning(refusal) => refusal.name(),
        Reason::Unknown => "unknown",
    }
}

fn kind(kind: io::ErrorKind) -> &'static str {
    use io::ErrorKind;
    match kind {
        ErrorKind::NotFound => "not_found",
        ErrorKind::PermissionDenied => "permission_denied",
        ErrorKind::ConnectionRefused => "connection_refused",
        ErrorKind::ConnectionReset => "connection_reset",
        ErrorKind::HostUnreachable => "host_unreachable",
        ErrorKind::NetworkUnreachable => "network_unreachable",
        ErrorKind::ConnectionAborted => "connection_aborted",
        ErrorKind::NotConnected => "not_connected",
        ErrorKind::AddrInUse => "addr_in_use",
        ErrorKind::AddrNotAvailable => "addr_not_available",
        ErrorKind::NetworkDown => "network_down",
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::AlreadyExists => "already_exists",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::TimedOut => "timed_out",
        ErrorKind::WriteZero => "write_zero",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        ErrorKind::OutOfMemory => "out_of_memory",
        // ErrorKind is non-exhaustive. This display-only fallback never changes
        // the exact typed category retained by the shared service completion.
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, Write},
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    fn observation() -> Result<service::SetupObservation> {
        // Only acceptance is exercised: the owner is never polled, so this
        // service opens no transport, attachment or authentication exchange.
        let plan = service::Prepared::unpolled_common_fixture()?;
        let (handle, _run) = service::channel();
        let key = handle
            .next_key()
            .map_err(|_| io::Error::other("fixture request key"))?;
        let accepted = handle
            .connect(plan, key)
            .map_err(|_| io::Error::other("fixture acceptance"))?;
        Ok(service::SetupObservation {
            operation: accepted.operation,
            stage: service::SetupStage::SocketBind,
            outcome: service::SetupOutcome::Failed,
            failure: Some(service::SetupFailure {
                kind: io::ErrorKind::AddrInUse,
                reason: service::SetupFailureReason::LocalIo,
            }),
            elapsed_micros: 7,
            original_timeout_micros: 3_000_000,
            runtime: None,
        })
    }

    fn projected(snapshot: service::SetupObservation) -> Result<Value> {
        project(snapshot).ok_or_else(|| io::Error::other("missing failure projection").into())
    }

    fn proc_path(fd: &impl AsRawFd) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
    }

    fn temporary() -> io::Result<File> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "l2tunnel-setup-output-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        std::fs::remove_file(path)?;
        Ok(file)
    }

    fn pipe() -> io::Result<(
        std::io::PipeReader,
        std::io::PipeWriter,
        super::super::output::Sink,
    )> {
        let (reader, writer) = std::io::pipe()?;
        let flags = rustix::fs::fcntl_getfl(&writer)?;
        let sink = super::super::output::Sink::reopen(&proc_path(&writer))?;
        assert_eq!(rustix::fs::fcntl_getfl(&writer)?, flags);
        Ok((reader, writer, sink))
    }

    #[test]
    fn exact_failure_projection_preserves_unknown_counters_as_null() -> Result {
        let snapshot = observation()?;
        assert_eq!(
            projected(snapshot)?,
            json!({
                "event": "secure_udp_setup_failed", "schema": 1,
                "operation": snapshot.operation.value(), "stage": "socket_bind", "outcome": "failed",
                "kind": "addr_in_use", "reason": "local_io", "elapsed_micros": 7,
                "original_timeout_micros": 3_000_000, "bootstrap": null, "control": null,
                "server_gate_cumulative": null, "member_attempts": null,
            })
        );
        let mut snapshot = snapshot;
        snapshot.runtime = Some(diagnostics::Observation::new(diagnostics::Stage::Noise));
        assert!(projected(snapshot)?["bootstrap"].is_null());
        assert!(projected(snapshot)?["control"].is_null());
        assert!(projected(snapshot)?["server_gate_cumulative"].is_null());
        assert!(projected(snapshot)?["member_attempts"].is_null());
        Ok(())
    }

    #[test]
    fn every_static_stage_and_reason_has_an_explicit_projection() {
        use service::{SetupFailureReason as FailureReason, SetupStage as Stage};
        for (value, expected) in [
            (Stage::Accepted, "accepted"),
            (Stage::SocketBind, "socket_bind"),
            (Stage::SocketConnect, "socket_connect"),
            (Stage::AdmissionOwner, "admission_owner"),
            (Stage::Configuration, "configuration"),
            (Stage::Admission, "admission"),
            (Stage::Noise, "noise"),
            (Stage::Membership, "membership"),
            (Stage::Attachment, "attachment"),
            (Stage::DriverReadiness, "driver_readiness"),
            (Stage::ReadyPublication, "ready_publication"),
        ] {
            assert_eq!(stage(value), expected);
        }
        use diagnostics::Reason;
        for (value, expected) in [
            (Reason::OriginalDeadline, "original_deadline"),
            (Reason::BootstrapDeadline, "bootstrap_deadline"),
            (Reason::MembershipDeadline, "membership_deadline"),
            (Reason::AdmissionAttempts, "admission_attempts"),
            (Reason::BootstrapAttempts, "bootstrap_attempts"),
            (Reason::JoiningAttempts, "joining_attempts"),
            (Reason::Configuration, "configuration"),
            (Reason::Entropy, "entropy"),
            (Reason::Authentication, "authentication"),
            (Reason::Protocol, "protocol"),
            (Reason::Cover, "cover"),
            (Reason::LocalIo, "local_io"),
            (Reason::Crypto, "crypto"),
            (Reason::Capacity, "capacity"),
            (Reason::CounterExhausted, "counter_exhausted"),
            (Reason::Clock, "clock"),
            (
                Reason::LiveTuning(l2tunnel::live_tuning::Refusal::RepairLimit),
                "live_tuning_repair_limit",
            ),
            (Reason::Unknown, "unknown"),
        ] {
            assert_eq!(runtime_reason(value), expected);
            assert_eq!(reason(FailureReason::Runtime(value)), expected);
        }
        for (value, expected) in [
            (FailureReason::OriginalDeadline, "original_deadline"),
            (FailureReason::LocalIo, "local_io"),
            (FailureReason::ReadinessEnded, "readiness_ended"),
            (FailureReason::Unknown, "unknown"),
        ] {
            assert_eq!(reason(value), expected);
        }
        assert_eq!(kind(io::ErrorKind::TimedOut), "timed_out");
        assert_eq!(kind(io::ErrorKind::PermissionDenied), "permission_denied");
        assert_eq!(kind(io::ErrorKind::Other), "other");
    }

    #[test]
    fn all_numeric_maxima_remain_a_small_fixed_failure_record() -> Result {
        let mut snapshot = observation()?;
        snapshot.elapsed_micros = u64::MAX;
        snapshot.original_timeout_micros = u64::MAX;
        snapshot.stage = service::SetupStage::ReadyPublication;
        snapshot.failure = Some(service::SetupFailure {
            kind: io::ErrorKind::NetworkUnreachable,
            reason: service::SetupFailureReason::Runtime(diagnostics::Reason::MembershipDeadline),
        });
        snapshot.runtime = Some(diagnostics::Observation {
            stage: diagnostics::Stage::Membership,
            // The operation's actual failure remains authoritative over a hint.
            reason: Some(diagnostics::Reason::Authentication),
            bootstrap: Some(l2tunnel_runtime::secure_udp::establish::Statistics {
                received_datagrams: u64::MAX,
                ignored_datagrams: u64::MAX,
                emitted_datagrams: u64::MAX,
                emitted_udp_bytes: u64::MAX,
                socket_sent_datagrams: u64::MAX,
                maintained_accepted_records: u64::MAX,
                maintained_accepted_record_bytes: u64::MAX,
                socket_sent_udp_bytes: u64::MAX,
                socket_drops: u64::MAX,
                socket_receive_errors: u64::MAX,
                noise_flights: u64::MAX,
                noise_duplicates: u64::MAX,
                gate_retries: u64::MAX,
                bootstrap_fresh: u64::MAX,
                bootstrap_replays: u64::MAX,
            }),
            control: Some(l2tunnel_udp_control::ControlStatistics {
                transmitted_packets: u64::MAX,
                transmitted_ip_bytes: u64::MAX,
                received_packets: u64::MAX,
                replay_packets: u64::MAX,
                send_bytes: usize::MAX,
                receive_bytes: usize::MAX,
            }),
            server_gate: Some(l2tunnel_udp_control::GateStatistics {
                validated_request_bytes: u64::MAX,
                response_bytes: u64::MAX,
                retained_sessions: usize::MAX,
            }),
            member_attempts: Some(u32::MAX),
        });
        let mut value = projected(snapshot)?;
        assert_eq!(value["reason"], "membership_deadline");
        assert_eq!(
            value["bootstrap"].as_object().map(|object| object.len()),
            Some(15)
        );
        assert_eq!(
            value["control"].as_object().map(|object| object.len()),
            Some(6)
        );
        assert_eq!(
            value["server_gate_cumulative"]
                .as_object()
                .map(|object| object.len()),
            Some(3)
        );
        assert_eq!(value["member_attempts"], u32::MAX);
        // Cover the numeric identifier width without manufacturing an accepted ID.
        value["operation"] = json!(u64::MAX);
        value["log_health"] = serde_json::to_value(super::super::output::Health {
            disabled: true,
            write_errors: u64::MAX,
            broken_pipe: u64::MAX,
            would_block: u64::MAX,
            projection_errors: u64::MAX,
            dropped_lines: u64::MAX,
            dropped_bytes: u64::MAX,
            written_bytes: u64::MAX,
            queue_bytes_high: u64::MAX,
            shutdown_timeouts: u64::MAX,
            unresolved_lines: u64::MAX,
            unresolved_bytes: u64::MAX,
        })?;
        assert!(serde_json::to_vec(&value)?.len() < 4096);
        Ok(())
    }

    #[test]
    fn nonfailed_or_missing_failure_is_not_reported_as_failed() -> Result {
        let snapshot = observation()?;
        let mut file = temporary()?;
        let mut sink = super::super::output::Sink::reopen(&proc_path(&file))?;
        for outcome in [
            service::SetupOutcome::Pending,
            service::SetupOutcome::Ready,
            service::SetupOutcome::Cancelled,
            service::SetupOutcome::OwnerClosed,
        ] {
            let mut other = snapshot;
            other.outcome = outcome;
            assert!(project(other).is_none());
            failed(other, &mut sink);
        }
        let mut missing = snapshot;
        missing.failure = None;
        assert!(project(missing).is_none());
        failed(missing, &mut sink);
        assert_eq!(sink.health.projection_errors, 5);
        assert_eq!(sink.health.written_bytes, 0);
        assert!(!sink.has_pending());
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        assert!(bytes.is_empty());
        Ok(())
    }

    #[test]
    fn regular_file_contains_one_exact_decodable_event_with_health() -> Result {
        let snapshot = observation()?;
        let mut file = temporary()?;
        file.write_all(b"existing prefix\n")?;
        file.rewind()?;
        let flags = rustix::fs::fcntl_getfl(&file)?;
        let mut sink = super::super::output::Sink::reopen(&proc_path(&file))?;
        failed(snapshot, &mut sink);
        assert_eq!(rustix::fs::fcntl_getfl(&file)?, flags);
        assert_eq!(file.stream_position()?, 0);
        assert!(!sink.has_pending());
        assert!(!sink.health.disabled);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let payload = bytes
            .strip_prefix(b"existing prefix\n")
            .ok_or_else(|| io::Error::other("overwritten prefix"))?;
        assert_eq!(payload.iter().filter(|byte| **byte == b'\n').count(), 1);
        let decoded: Value = serde_json::from_slice(payload)?;
        let mut expected = projected(snapshot)?;
        expected["log_health"] = serde_json::to_value(super::super::output::Health::default())?;
        assert_eq!(decoded, expected);
        assert_eq!(sink.health.written_bytes, u64::try_from(payload.len())?);
        assert!(payload.len() <= 4096);
        Ok(())
    }

    #[test]
    fn full_owned_pipe_preserves_inherited_flags_and_bounds_failure_queue() -> Result {
        let snapshot = observation()?;
        let (_reader, writer, mut sink) = pipe()?;
        let flags = rustix::fs::fcntl_getfl(&writer)?;
        let nonblocking = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC;
        let mut filler = OpenOptions::new()
            .append(true)
            .custom_flags(i32::try_from(nonblocking.bits())?)
            .open(proc_path(&writer))?;
        let mut blocked = false;
        let mut filled = 0usize;
        for _ in 0..4096 {
            match filler.write(&[b'P'; 4096]) {
                Ok(count) => {
                    filled += count;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert!(blocked && filled > 0);
        // A failed PIPE_BUF-sized write can leave a smaller tail of capacity.
        blocked = false;
        for _ in 0..=4096 {
            match filler.write(b"P") {
                Ok(1) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                Ok(_) => return Err(io::Error::other("unexpected filler write").into()),
                Err(error) => return Err(error.into()),
            }
        }
        assert!(blocked);
        for _ in 0..super::super::output::MAX_LINES + 3 {
            failed(snapshot, &mut sink);
        }
        assert_eq!(rustix::fs::fcntl_getfl(&writer)?, flags);
        assert!(!sink.health.disabled);
        assert!(sink.has_pending());
        assert_eq!(sink.health.dropped_lines, 3);
        assert_eq!(sink.health.written_bytes, 0);
        assert_eq!(sink.health.write_errors, 0);
        assert!(sink.health.would_block > 0);
        assert!(
            sink.health.queue_bytes_high <= u64::try_from(super::super::output::MAX_LINES * 4096)?
        );
        Ok(())
    }

    #[test]
    fn broken_owned_pipe_is_nonfatal_and_does_not_change_original_flags() -> Result {
        let snapshot = observation()?;
        let (reader, writer, mut sink) = pipe()?;
        let flags = rustix::fs::fcntl_getfl(&writer)?;
        drop(reader);
        failed(snapshot, &mut sink);
        assert_eq!(rustix::fs::fcntl_getfl(&writer)?, flags);
        assert!(sink.health.disabled);
        assert_eq!(sink.health.broken_pipe, 1);
        assert_eq!(sink.health.write_errors, 1);
        assert_eq!(sink.health.dropped_lines, 1);
        assert!(!sink.has_pending());
        failed(snapshot, &mut sink);
        assert_eq!(sink.health.broken_pipe, 1);
        assert_eq!(sink.health.write_errors, 1);
        assert_eq!(sink.health.dropped_lines, 2);
        Ok(())
    }
}

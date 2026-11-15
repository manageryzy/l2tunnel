//! Bounded public plan inspection and actual shared-service event projections.
//! The caller owns stdout, logger health and I/O; these values create no runtime.

use crate::secure_udp::{transaction_profile::Profile, transaction_status::CanonicalConfiguration};
use l2tunnel_security::Role;
use serde_json::{Value, json};
use std::io::{self, Write};

#[cfg(target_os = "linux")]
use crate::service::{SecureUdpTransactionFrame, Terminal};

/// Leave bounded logger-health and newline space inside the existing128KiB line.
pub(super) const MAX_VALUE_BYTES: usize = 128 * 1024 - 2048;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

struct Count(usize);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_VALUE_BYTES)
            .ok_or_else(|| invalid("generic CLI output exceeds its value bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn bounded(value: Value) -> io::Result<Value> {
    serde_json::to_writer(&mut Count(0), &value)
        .map_err(|_| invalid("generic CLI output exceeds its value bound"))?;
    Ok(value)
}

/// Inspect the complete checked requested plan, without authenticating or starting it.
pub(super) fn inspection(profile: &Profile, role: Role) -> io::Result<Value> {
    let settings = profile.settings();
    let peers = profile.peers();
    let contract = profile.runtime_contract(role)?;
    let parameters = profile.parameters();
    let configurations = profile
        .catalog()
        .configurations(profile.envelope())
        .into_iter()
        .map(CanonicalConfiguration::from_configuration)
        .collect::<io::Result<Vec<_>>>()?;
    let (role, local, peer) = match role {
        Role::Initiator => (
            "initiator",
            settings.gate.path.client,
            settings.gate.path.server,
        ),
        Role::Responder => (
            "responder",
            settings.gate.path.server,
            settings.gate.path.client,
        ),
    };
    let report_interval = contract.config().report_interval.map(|interval| {
        json!({
            "seconds": interval.as_secs(),
            "nanoseconds": interval.subsec_nanos(),
        })
    });
    bounded(json!({
        "event": "secure_udp_transaction_plan",
        "schema": 1,
        "backend": "generic_swift_v1",
        "carrier": match settings.cover.appearance {
            l2tunnel_cover::Appearance::QuicLike => "quic-like",
            l2tunnel_cover::Appearance::MediaLike => "media-like",
        },
        "algorithm": "swift",
        "protection": "chacha20-poly1305",
        "role": role,
        "requested": true,
        "validated": true,
        "authenticated": false,
        "resource_preallocation_complete": false,
        "configuration": profile.configuration()?.0,
        "envelope": profile.envelope().as_bytes(),
        "catalog": profile.catalog().root().as_bytes(),
        "data_digest": profile.data_digest().0,
        "initial": CanonicalConfiguration::from_configuration(profile.initial())?,
        "catalog_members": configurations.len(),
        "configurations": configurations,
        "parameters": {
            "retry_ms": parameters.protocol.retry_ms,
            "phase_timeout_ms": parameters.protocol.phase_timeout_ms,
            "reconcile_timeout_ms": parameters.protocol.reconcile_timeout_ms,
            "max_operation_ms": parameters.max_operation_ms,
            "retained_bytes": u64::try_from(parameters.retained_bytes).map_err(io::Error::other)?,
        },
        // A local observation value; report cadence is excluded from E/H0.
        "report_interval": report_interval,
        "member": settings.member.0,
        "initiator_noise": peers.initiator.0,
        "responder_noise": peers.responder.0,
        "local": local.to_string(),
        "peer": peer.to_string(),
    }))
}

#[cfg(target_os = "linux")]
fn actual(
    frame: &SecureUdpTransactionFrame,
    expected_generation: u64,
) -> io::Result<crate::secure_udp::transaction_status::Status> {
    if frame.generation != expected_generation {
        return Err(invalid(
            "generic CLI event belongs to another service generation",
        ));
    }
    frame.status()
}

/// Publish only actual completed readiness, without inventing a runtime snapshot.
#[cfg(target_os = "linux")]
pub(super) fn ready(
    frame: &SecureUdpTransactionFrame,
    expected_generation: u64,
) -> io::Result<Value> {
    let status = actual(frame, expected_generation)?;
    if frame.runtime.is_none()
        || !status.running
        || status.terminal.is_some()
        || frame.service_terminal.is_some()
    {
        return Err(invalid("generic CLI readiness has no live runtime report"));
    }
    bounded(json!({"event":"secure_udp_transaction_ready", "schema":1, "status":status}))
}

/// Retain exact requested/current/physical and optional runtime observations.
#[cfg(target_os = "linux")]
pub(super) fn status(
    frame: &SecureUdpTransactionFrame,
    expected_generation: u64,
) -> io::Result<Value> {
    let status = actual(frame, expected_generation)?;
    bounded(json!({"event":"secure_udp_transaction_status", "schema":1, "status":status}))
}

/// Publish an actual matching service termination without changing runtime facts.
#[cfg(target_os = "linux")]
pub(super) fn terminal(
    frame: &SecureUdpTransactionFrame,
    expected_generation: u64,
    outcome: Terminal,
) -> io::Result<Value> {
    let status = actual(frame, expected_generation)?;
    if frame.service_terminal != Some(outcome) || status.running {
        return Err(invalid(
            "generic CLI terminal differs from actual service release",
        ));
    }
    bounded(json!({
        "event":"secure_udp_transaction_terminal", "schema":1,
        "outcome":format!("{outcome:?}"), "status":status,
    }))
}

#[cfg(test)]
#[path = "transaction_cli_output_tests.rs"]
mod tests;

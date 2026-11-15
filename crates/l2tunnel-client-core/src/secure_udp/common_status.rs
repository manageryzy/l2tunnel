//! Portable bounded version4 observations, independent of native runtime owners.

use l2tunnel::record_configuration::{CONFIGURATION_BYTES, Configuration};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{fmt, io};

/// Exact length of the lowercase hexadecimal complete configuration value.
pub const CANONICAL_CHARACTERS: usize = CONFIGURATION_BYTES * 2;

/// Checked complete canonical bytes; never a rounded SwiftPolicyV1 patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalConfiguration(String);

impl CanonicalConfiguration {
    /// Parse exact lowercase canonical text through the existing complete decoder.
    pub fn parse(text: &str) -> io::Result<Self> {
        decode_configuration(text)?;
        Ok(Self(text.to_owned()))
    }
    /// Encode one existing checked complete value without changing any field.
    pub fn from_configuration(configuration: Configuration) -> io::Result<Self> {
        let mut bytes = [0; CONFIGURATION_BYTES];
        configuration.encode_into(&mut bytes).map_err(invalid)?;
        let mut text = String::with_capacity(CANONICAL_CHARACTERS);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        Ok(Self(text))
    }
    /// Decode using the existing pure complete-configuration parser.
    pub fn configuration(&self) -> io::Result<Configuration> {
        decode_configuration(&self.0)
    }
    /// Exact canonical lowercase hexadecimal text, without an alternate parser.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn decode_configuration(text: &str) -> io::Result<Configuration> {
    if text.len() != CANONICAL_CHARACTERS
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "complete configuration requires2608 lowercase hex characters",
        ));
    }
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let mut bytes = [0; CONFIGURATION_BYTES];
    for (output, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *output = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    let value = Configuration::decode(&bytes).map_err(invalid)?;
    let mut canonical = [0; CONFIGURATION_BYTES];
    value.encode_into(&mut canonical).map_err(invalid)?;
    if canonical != bytes {
        return Err(invalid("noncanonical complete configuration"));
    }
    Ok(value)
}

impl Serialize for CanonicalConfiguration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for CanonicalConfiguration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl de::Visitor<'_> for Visitor {
            type Value = CanonicalConfiguration;
            fn expecting(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                output.write_str(
                    "exactly2608 lowercase hex characters encoding a complete Common configuration",
                )
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                CanonicalConfiguration::parse(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

// These portable accounting types retain the established schema semantics.
pub use super::transaction_status::{
    Control, Liveness, Native, Operation, Phase, Scope, Security, Storage, Wire,
};
/// Maximum full configurations returned by one generation-bound catalog request.
pub const CATALOG_PAGE_LIMIT: u16 = 4;
/// One finite page of the full authenticated catalog; no supported entries are pruned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogPage {
    /// First index in canonical catalog order.
    pub offset: u16,
    /// Exact complete catalog size.
    pub total: u16,
    /// Next index, or None at the exact end.
    pub next: Option<u16>,
    /// Complete anchored configurations.
    pub configurations: Vec<CanonicalConfiguration>,
}
/// Actual per-direction rolling scheduler limits for one Driver service turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingWork {
    /// GF operations per direction.
    pub field: u64,
    /// Copied bytes per direction.
    pub copies: u64,
    /// Metadata operations per direction.
    pub metadata: u64,
}
/// Separate truthful portable status for explicit finite-catalog generic selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Exact service generation.
    pub generation: u64,
    /// Advisory actual next service key at local projection time; never a reservation.
    pub next_request_key: Option<u64>,
    /// Explicit carrier appearance.
    pub carrier: String,
    /// Data algorithm, separate from carrier selection.
    pub algorithm: String,
    /// Actual required integrity/confidentiality profile.
    pub protection: String,
    /// Explicit complete Common backend contract identifier.
    pub backend: String,
    /// Actual readiness, optionally overlaid false by service termination.
    pub running: bool,
    /// Actual runtime sample time, absent before a report exists.
    pub elapsed_micros: Option<u64>,
    /// Retained bounded runtime terminal category, separate from service stop.
    pub terminal: Option<String>,
    /// Service terminal overlay; does not alter retained runtime facts.
    pub service_terminal: Option<String>,
    /// Actual public authenticated session identity.
    pub session: [u8; 16],
    /// Final authenticated public Noise transcript.
    pub transcript: [u8; 32],
    /// Exact public outer prologue binding.
    pub outer: [u8; 32],
    /// Authenticated existing Ed25519 client member identity.
    pub member: [u8; 32],
    /// Ordered fixed initiating Noise pin.
    pub initiator_noise: [u8; 32],
    /// Ordered fixed responding Noise pin.
    pub responder_noise: [u8; 32],
    /// Actual connected local endpoint.
    pub local: String,
    /// Actual connected peer endpoint.
    pub peer: String,
    /// Recomputed authenticated setup/Control digest H0.
    pub configuration: [u8; 32],
    /// Exact anchor-free complete catalog root.
    pub catalog: [u8; 32],
    /// Full catalog member count; no truncation of the supported set.
    pub catalog_members: u16,
    /// Exact requested startup complete configuration.
    pub initial: CanonicalConfiguration,
    /// Actual Bank complete configuration; absent before a runtime report.
    pub current: Option<CanonicalConfiguration>,
    /// Actual retained local complete request, never substituted for current.
    pub requested: Option<CanonicalConfiguration>,
    /// Actual Bank epoch.
    pub epoch: Option<u64>,
    /// Actual management Peer phase.
    pub phase: Option<Phase>,
    /// Actual retained leased operation.
    pub operation: Option<Operation>,
    /// Actual physically installed data scope, distinct from Bank/requested values.
    pub physical_scope: Option<Scope>,
    /// Actual Bank requested-layout charges.
    pub storage: Option<Storage>,
    /// Actual local selected IP-wire rate and channel widths.
    pub send_rate: Option<u64>,
    /// Actual incoming directional IP-wire rate.
    pub receive_rate: Option<u64>,
    /// Actual outgoing selected MUX width.
    pub send_channels: Option<u16>,
    /// Actual incoming selected MUX width.
    pub receive_channels: Option<u16>,
    /// Actual qualification flag; false while control/Peer storage is incomplete.
    pub resource_preallocation_complete: bool,
    /// Actual fully provisioned native queue capacity subtotal.
    pub native_storage_capacity_bytes: Option<u64>,
    /// Actual seven byte-workspace capacities.
    pub workspace_capacity_bytes: Option<u64>,
    /// Actual two sole-loop input capacities.
    pub loop_input_capacity_bytes: Option<u64>,
    /// Actual attempted/accepted/received wire summary.
    pub wire: Option<Wire>,
    /// Actual native physical and queue summary.
    pub native: Option<Native>,
    /// Actual fixed control retained custody.
    pub control: Option<Control>,
    /// Actual nonsecret outgoing security identifiers.
    pub security: Option<Security>,
    /// Actual fixed-scope authenticated challenge state.
    pub liveness: Option<Liveness>,
    /// Complete selected catalog changes are supported, distinct from cross-profile SW-11.
    pub configuration_change: bool,
    /// Only the authenticated initiator is the management coordinator.
    pub coordinator: bool,
    /// Fresh-authenticated service reconnect is supported.
    pub reconnect: bool,
    /// Actual selected runtime supports catalogued record-family transitions.
    pub cross_profile_switching: bool,
    /// Full retained-state recovery remains a separate qualification gate.
    pub retained_state_recovery: bool,
    /// Full runtime fresh-DH lifecycle remains a separate qualification gate.
    pub fresh_rekey: bool,
    /// Actual optional authenticated work policy. Each step caps send and receive
    /// independently; at most two live epochs produce four directional caps/turn.
    pub rolling_work: Option<RollingWork>,
    /// Actual directional scheduler step count, never inferred from packet count.
    pub rolling_scheduler_steps: Option<u64>,
    /// Actual cumulative GF/copy/metadata work consumed.
    pub rolling_work_used: Option<[u64; 3]>,
    /// Complete catalog page only on an explicit bounded catalog request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_page: Option<CatalogPage>,
    /// Actual retained service result, present only in a completed switch reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<SwitchResult>,
}

fn invalid(message: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

#[cfg(unix)]
mod observe {
    use super::*;
    use crate::secure_udp::{common_transaction_profile::Profile, member};
    use l2tunnel_management as mg;
    use l2tunnel_runtime::secure_udp::transport;
    use l2tunnel_security::Role;
    fn number(value: usize) -> io::Result<u64> {
        u64::try_from(value).map_err(invalid)
    }
    impl Status {
        pub(crate) fn observe(
            profile: &Profile,
            info: member::Info,
            generation: u64,
            snapshot: Option<&transport::CommonSnapshot>,
        ) -> io::Result<Self> {
            let configuration = profile.configuration()?;
            let settings = profile.settings();
            let expected = settings
                .runtime(info.role, profile.peers())?
                .expected_binding(profile.peers(), info.binding.session)
                .map_err(invalid)?;
            let path = settings.gate.path;
            let (local, peer) = match info.role {
                Role::Initiator => (path.client, path.server),
                Role::Responder => (path.server, path.client),
            };
            if info.peers != profile.peers()
                || info.authenticated.configuration != configuration.0
                || info.authenticated.session != info.binding.session
                || info.authenticated.carrier != expected.carrier
                || info.authenticated.outer != expected.outer
                || info.authenticated.member != expected.member
                || info.member != settings.member
                || info.local_addr != local
                || info.peer_addr != peer
                || snapshot
                    .is_some_and(|value| value.info != info || value.configuration != configuration)
            {
                return Err(invalid(
                    "transaction observation differs from retained authenticated plan",
                ));
            }
            if let Some(value) = snapshot {
                profile
                    .runtime_contract(info.role)?
                    .resolve(value.current)?;
                if let Some(requested) = value.requested {
                    profile.runtime_contract(info.role)?.resolve(requested)?;
                }
                if value.operation.is_some_and(|operation| {
                    let identity = operation.identity();
                    identity.session.0 != info.binding.session.0
                        || identity.role
                            != match info.role {
                                Role::Initiator => mg::Role::Client,
                                Role::Responder => mg::Role::Server,
                            }
                }) {
                    return Err(invalid(
                        "transaction operation belongs to another session or role",
                    ));
                }
            }
            let counters = snapshot.map(|value| value.counters);
            Ok(Self {
                generation,
                next_request_key: None,
                carrier: match settings.cover.appearance {
                    l2tunnel_cover::Appearance::QuicLike => "quic-like",
                    l2tunnel_cover::Appearance::MediaLike => "media-like",
                }
                .into(),
                algorithm: "common-records".into(),
                protection: "chacha20-poly1305".into(),
                backend: "common_records_v2".into(),
                running: snapshot.is_some_and(|value| value.running),
                elapsed_micros: snapshot.map(|value| value.elapsed_micros),
                terminal: snapshot
                    .and_then(|value| value.terminal.map(|reason| format!("{reason:?}"))),
                service_terminal: None,
                session: info.binding.session.0,
                transcript: info.binding.transcript,
                outer: info.authenticated.outer,
                member: info.member.0,
                initiator_noise: info.peers.initiator.0,
                responder_noise: info.peers.responder.0,
                local: info.local_addr.to_string(),
                peer: info.peer_addr.to_string(),
                configuration: configuration.0,
                catalog: *profile.catalog().root().as_bytes(),
                catalog_members: u16::try_from(profile.catalog().descriptors().len())
                    .map_err(invalid)?,
                initial: CanonicalConfiguration::from_configuration(profile.initial())?,
                current: snapshot
                    .map(|value| CanonicalConfiguration::from_configuration(value.current))
                    .transpose()?,
                requested: snapshot
                    .and_then(|value| value.requested)
                    .map(CanonicalConfiguration::from_configuration)
                    .transpose()?,
                epoch: snapshot.map(|value| value.epoch.0),
                phase: snapshot.map(|value| value.phase.into()),
                operation: snapshot.and_then(|value| value.operation).map(Into::into),
                physical_scope: snapshot.map(|value| value.physical_scope.into()),
                storage: snapshot
                    .map(|value| {
                        Ok::<_, io::Error>(Storage {
                            limit_bytes: number(value.storage.limit_bytes)?,
                            fixed_bytes: number(value.storage.fixed_bytes)?,
                            external_bytes: number(value.storage.external_bytes)?,
                            engine_bytes: number(value.storage.engine_bytes)?,
                            building_bytes: number(value.storage.building_bytes)?,
                            peak_bytes: number(value.storage.peak_bytes)?,
                        })
                    })
                    .transpose()?,
                send_rate: snapshot.map(|value| value.send_rate),
                receive_rate: snapshot.map(|value| value.receive_rate),
                send_channels: snapshot.map(|value| value.send_channels),
                receive_channels: snapshot.map(|value| value.receive_channels),
                resource_preallocation_complete: snapshot
                    .is_some_and(|value| value.resource_preallocation_complete),
                native_storage_capacity_bytes: counters
                    .map(|value| number(value.native_storage_capacity_bytes))
                    .transpose()?,
                workspace_capacity_bytes: counters
                    .map(|value| number(value.workspace_capacity_bytes))
                    .transpose()?,
                loop_input_capacity_bytes: counters
                    .map(|value| number(value.loop_input_capacity_bytes))
                    .transpose()?,
                wire: counters.map(|value| Wire {
                    packets: value.wire_packets,
                    ip_bytes: value.wire_bytes,
                    socket_accepted_packets: value.socket_accepted_packets,
                    socket_accepted_ip_bytes: value.socket_accepted_ip_bytes,
                    socket_drops: value.socket_drops,
                    socket_receive_errors: value.socket_receive_errors,
                    received_packets: value.received_packets,
                    rejected_packets: value.rejected_packets,
                    replay_rejections: value.replay_rejections,
                }),
                native: counters
                    .map(|value| {
                        Ok::<_, io::Error>(Native {
                            read: value.native_read,
                            written: value.native_written,
                            oversize: value.native_oversize,
                            backpressure_drops: value.native_backpressure_drops,
                            pending_packets: number(value.native_pending_packets)?,
                            pending_bytes: number(value.native_pending_bytes)?,
                        })
                    })
                    .transpose()?,
                control: snapshot
                    .map(|value| {
                        Ok::<_, io::Error>(Control {
                            send_records: number(value.control.send_records)?,
                            send_bytes: number(value.control.send_bytes)?,
                            receive_records: number(value.control.receive_records)?,
                            receive_bytes: number(value.control.receive_bytes)?,
                        })
                    })
                    .transpose()?,
                security: counters.map(|value| Security {
                    user_number: value.user_number.map(|number| number.0),
                    control_number: value.control_number.map(|number| number.0),
                    user_generation: value.user_generation.map(|generation| generation.0),
                    control_generation: value.control_generation.map(|generation| generation.0),
                }),
                liveness: snapshot.map(|value| Liveness {
                    ping: value.liveness.outstanding,
                    deadline_micros: value.liveness.deadline_micros,
                    last_verified_micros: value.liveness.last_verified_micros,
                    last_pong_micros: value.liveness.last_pong_micros,
                }),
                configuration_change: true,
                coordinator: info.role == Role::Initiator,
                reconnect: true,
                cross_profile_switching: true,
                retained_state_recovery: false,
                fresh_rekey: false,
                rolling_work: profile
                    .runtime_contract(info.role)?
                    .resources()
                    .rolling_work
                    .map(|work| {
                        Ok::<_, io::Error>(RollingWork {
                            field: number(work.field)?,
                            copies: number(work.copies)?,
                            metadata: number(work.metadata)?,
                        })
                    })
                    .transpose()?,
                rolling_scheduler_steps: snapshot.map(|value| value.rolling_scheduler_steps),
                rolling_work_used: snapshot.map(|value| value.rolling_work_used),
                catalog_page: None,
                result: None,
            })
        }
    }
}

/// Exact result of the existing shared actor operation; never a requested-as-current projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchResult {
    /// Original complete target, including on a retained-key replay.
    pub configuration: CanonicalConfiguration,
    /// Actual completed epoch, absent on a runtime refusal.
    pub epoch: Option<u64>,
    /// Actual bounded runtime outcome category.
    pub outcome: String,
    /// Actual retained shared service operation identifier.
    pub operation: u64,
    /// Exact supplied key, including on an idempotent replay.
    pub request_key: u64,
}

#[cfg(test)]
#[path = "common_status_tests.rs"]
pub(crate) mod tests;

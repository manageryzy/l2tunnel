//! Portable bounded version3 observations, independent of native runtime owners.

use l2tunnel::swift_configuration::{CONFIGURATION_BYTES, Configuration};
use l2tunnel_management::transaction::Configuration as _;
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
            "complete configuration requires608 lowercase hex characters",
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
                    "exactly608 lowercase hex characters encoding a complete Swift configuration",
                )
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                CanonicalConfiguration::parse(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

/// Actual generic management phase; no parallel frontend state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// No management operation is pending.
    Idle,
    /// Coordinator is preparing the actual target engine.
    Staging,
    /// Coordinator awaits the follower's readiness.
    AwaitReady,
    /// Coordinator awaits physical directional drain.
    Draining,
    /// Coordinator awaits the peer's independent barrier.
    AwaitBarrier,
    /// Commit may have reached the peer.
    AwaitCommitAck,
    /// Both commits are known; old reader retirement is pending.
    AwaitRetireAck,
    /// Pre-commit abort is awaiting confirmation.
    Aborting,
    /// Commit/retirement custody remains uncertain.
    Uncertain,
    /// Follower is preparing its actual target engine.
    FollowerStaging,
    /// Follower awaits barrier/drain evidence.
    FollowerReady,
    /// Follower has a barrier but lacks local drain evidence.
    FollowerDraining,
    /// Follower has both drains and awaits commit.
    FollowerDrained,
    /// Follower committed while retaining the old reader.
    FollowerCommitted,
    /// Terminal protocol failure; no rollback is implied.
    Failed,
}

/// Exact data epoch and full canonical digest, separate from setup H0.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Complete logical data epoch.
    pub epoch: u64,
    /// Full configuration digest at that epoch.
    pub configuration: [u8; 32],
}

/// Actual retained leased operation, including its unchanged original expiry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    /// Actual authenticated global role of this peer.
    pub role: String,
    /// Fixed physical management lane.
    pub lane: u32,
    /// Logical management endpoint; not a member identifier or MAC address.
    pub local_endpoint: u32,
    /// Logical peer endpoint.
    pub remote_endpoint: u32,
    /// Exact monotonically increasing proposal attempt.
    pub attempt: u64,
    /// Complete target epoch.
    pub epoch: u64,
    /// Complete target digest.
    pub configuration: [u8; 32],
    /// Original data scope whose command/retry authority is retained.
    pub origin: Scope,
    /// Original injected millisecond expiry; never a renewed phase deadline.
    pub expires_millis: u64,
}

/// Actual requested-layout accounting; not RSS or complete resource qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    /// Configured owner ceiling.
    pub limit_bytes: u64,
    /// Inline engine-set layouts.
    pub fixed_bytes: u64,
    /// Caller-accounted known external capacity subtotal.
    pub external_bytes: u64,
    /// Published engine heap layouts.
    pub engine_bytes: u64,
    /// Target construction precharge.
    pub building_bytes: u64,
    /// Highest admitted combined layout charge.
    pub peak_bytes: u64,
}

/// Fixed native grammar of one local direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// Complete Ethernet frames.
    Ethernet,
    /// Complete IP packets.
    Ip,
}

/// Every actual local directional field, without rate/fraction rounding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Direction {
    /// Full configured IP-wire bytes per second.
    pub bytes_per_second: u64,
    /// Connection-affinity channel count.
    pub channels: u64,
    /// Fixed native grammar.
    pub layer: Layer,
    /// Largest uncompressed native packet.
    pub max_native: u64,
    /// Maximum Swift datagram body.
    pub datagram_bytes: u64,
    /// Maximum linear-repair support, separate from source ARQ flight.
    pub window: u64,
    /// Exact repair fraction numerator.
    pub repair_numerator: u64,
    /// Exact repair fraction denominator.
    pub repair_denominator: u64,
    /// Maximum retained unconfirmed source count.
    pub flow_sources: u64,
    /// Packing queue bound.
    pub queue_bytes: u64,
    /// Maximum tagged/compressed native record size.
    pub max_packet: u64,
    /// Partial source flush interval in microseconds.
    pub flush_micros: u64,
    /// Feedback interval in microseconds.
    pub feedback_micros: u64,
    /// Tail repair interval in microseconds.
    pub tail_micros: u64,
    /// Minimum retransmit interval in microseconds.
    pub min_rto_micros: u64,
    /// Maximum retransmit interval in microseconds.
    pub max_rto_micros: u64,
}

/// Actual attempted wire, socket acceptance and received-record observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wire {
    /// Attempted complete-wire packet charge.
    pub packets: u64,
    /// Attempted complete IP-wire byte charge.
    pub ip_bytes: u64,
    /// Native UDP socket accepted datagrams; not physical wire proof.
    pub socket_accepted_packets: u64,
    /// Socket-accepted IP byte cost.
    pub socket_accepted_ip_bytes: u64,
    /// Classified transient send drops.
    pub socket_drops: u64,
    /// Classified transient receive errors.
    pub socket_receive_errors: u64,
    /// Complete received datagrams examined.
    pub received_packets: u64,
    /// Rejected authentication/parser/scope inputs.
    pub rejected_packets: u64,
    /// Authenticated common security replay rejections.
    pub replay_rejections: u64,
}

/// Native admission, actual physical completion and retained-output pressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Native {
    /// Complete packets admitted from the native source.
    pub read: u64,
    /// Actual PacketDevice write completions, never extraction/enqueue counts.
    pub written: u64,
    /// Oversized native input.
    pub oversize: u64,
    /// Swift input refused under native output pressure.
    pub backpressure_drops: u64,
    /// Actual pending complete native packets.
    pub pending_packets: u64,
    /// Actual pending native payload bytes.
    pub pending_bytes: u64,
}

/// Whole control owner's actual retained reliable delivery custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Control {
    /// Retained outbound records.
    pub send_records: u64,
    /// Retained outbound bytes.
    pub send_bytes: u64,
    /// Inbound records awaiting local custody/dispatch.
    pub receive_records: u64,
    /// Retained inbound bytes.
    pub receive_bytes: u64,
}

/// Public outgoing security identifiers; generation is not fresh-DH evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    /// Last User sealing packet number, if any.
    pub user_number: Option<u64>,
    /// Last fixed-Control sealing packet number, if any.
    pub control_number: Option<u64>,
    /// Actual User key generation.
    pub user_generation: Option<u64>,
    /// Actual Control key generation.
    pub control_generation: Option<u64>,
}

/// Actual authenticated fixed-scope challenge state, in runtime microseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Liveness {
    /// The outstanding challenge identifier, if present.
    pub ping: Option<u64>,
    /// Its original expiry; never extended by a stale Pong.
    pub deadline_micros: Option<u64>,
    /// Last fresh authenticated record.
    pub last_verified_micros: Option<u64>,
    /// Last fresh valid matching Pong.
    pub last_pong_micros: Option<u64>,
}

/// Separate truthful portable status for explicit finite-catalog generic selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// Exact service generation.
    pub generation: u64,
    /// Explicit carrier appearance.
    pub carrier: String,
    /// Data algorithm, separate from carrier selection.
    pub algorithm: String,
    /// Actual required integrity/confidentiality profile.
    pub protection: String,
    /// Explicit generic Swift control contract identifier.
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
    /// Actual complete local outgoing policy, including partial directional crossings.
    pub send: Option<Direction>,
    /// Actual complete local incoming policy.
    pub receive: Option<Direction>,
    /// Actual Bank requested-layout charges.
    pub storage: Option<Storage>,
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
    /// Current engine unconfirmed sources; not native pending output.
    pub swift_unconfirmed: Option<u64>,
    /// Complete selected catalog changes are supported, distinct from cross-profile SW-11.
    pub configuration_change: bool,
    /// Only the authenticated initiator is the management coordinator.
    pub coordinator: bool,
    /// Fresh-authenticated service reconnect is supported.
    pub reconnect: bool,
    /// Full other-record-profile switching remains a separate requirement.
    pub cross_profile_switching: bool,
    /// Default retained-state recovery remains incomplete.
    pub retained_state_recovery: bool,
    /// Periodic fresh-DH lifecycle remains incomplete.
    pub fresh_rekey: bool,
}

fn invalid(message: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}

#[cfg(unix)]
mod observe {
    use super::*;
    use crate::secure_udp::{member, transaction_profile::Profile};
    use l2tunnel_management::{self as mg, transaction};
    use l2tunnel_runtime::secure_udp::transport;
    use l2tunnel_security::Role;
    use l2tunnel_swift::{policy, records, storage};

    fn number(value: usize) -> io::Result<u64> {
        u64::try_from(value).map_err(invalid)
    }

    impl From<transaction::Phase> for Phase {
        fn from(value: transaction::Phase) -> Self {
            match value {
                transaction::Phase::Idle => Self::Idle,
                transaction::Phase::Staging => Self::Staging,
                transaction::Phase::AwaitReady => Self::AwaitReady,
                transaction::Phase::Draining => Self::Draining,
                transaction::Phase::AwaitBarrier => Self::AwaitBarrier,
                transaction::Phase::AwaitCommitAck => Self::AwaitCommitAck,
                transaction::Phase::AwaitRetireAck => Self::AwaitRetireAck,
                transaction::Phase::Aborting => Self::Aborting,
                transaction::Phase::Uncertain => Self::Uncertain,
                transaction::Phase::FollowerStaging => Self::FollowerStaging,
                transaction::Phase::FollowerReady => Self::FollowerReady,
                transaction::Phase::FollowerDraining => Self::FollowerDraining,
                transaction::Phase::FollowerDrained => Self::FollowerDrained,
                transaction::Phase::FollowerCommitted => Self::FollowerCommitted,
                transaction::Phase::Failed => Self::Failed,
            }
        }
    }
    impl From<l2tunnel::secure_record::Scope> for Scope {
        fn from(value: l2tunnel::secure_record::Scope) -> Self {
            Self {
                epoch: value.epoch.0,
                configuration: value.configuration.0,
            }
        }
    }
    impl From<mg::session_control::Scope> for Scope {
        fn from(value: mg::session_control::Scope) -> Self {
            Self {
                epoch: value.epoch.0,
                configuration: value.digest.0,
            }
        }
    }
    impl From<transaction::Operation> for Operation {
        fn from(value: transaction::Operation) -> Self {
            let identity = value.identity();
            let ticket = value.ticket();
            Self {
                role: match identity.role {
                    mg::Role::Client => "initiator",
                    mg::Role::Server => "responder",
                }
                .into(),
                lane: identity.lane.0,
                local_endpoint: identity.local.0,
                remote_endpoint: identity.remote.0,
                attempt: ticket.attempt,
                epoch: ticket.epoch.0,
                configuration: ticket.digest.0,
                origin: value.origin().into(),
                expires_millis: value.expires().0,
            }
        }
    }
    impl TryFrom<storage::Usage> for Storage {
        type Error = io::Error;
        fn try_from(value: storage::Usage) -> io::Result<Self> {
            Ok(Self {
                limit_bytes: number(value.limit_bytes)?,
                fixed_bytes: number(value.fixed_bytes)?,
                external_bytes: number(value.external_bytes)?,
                engine_bytes: number(value.engine_bytes)?,
                building_bytes: number(value.building_bytes)?,
                peak_bytes: number(value.peak_bytes)?,
            })
        }
    }
    impl TryFrom<policy::Direction> for Direction {
        type Error = io::Error;
        fn try_from(value: policy::Direction) -> io::Result<Self> {
            let records = value.records;
            let codec = records.codec;
            Ok(Self {
                bytes_per_second: value.bytes_per_second,
                channels: number(records.channels)?,
                layer: match records.layer {
                    records::Layer::Ethernet => Layer::Ethernet,
                    records::Layer::Ip => Layer::Ip,
                },
                max_native: number(records.max_native)?,
                datagram_bytes: number(codec.datagram_bytes)?,
                window: number(codec.window)?,
                repair_numerator: u64::from(codec.repair_numerator),
                repair_denominator: u64::from(codec.repair_denominator),
                flow_sources: number(codec.flow_sources)?,
                queue_bytes: number(codec.queue_bytes)?,
                max_packet: number(codec.max_packet)?,
                flush_micros: codec.flush_micros,
                feedback_micros: codec.feedback_micros,
                tail_micros: codec.tail_micros,
                min_rto_micros: codec.min_rto_micros,
                max_rto_micros: codec.max_rto_micros,
            })
        }
    }

    impl Status {
        pub(crate) fn observe(
            profile: &Profile,
            info: member::Info,
            generation: u64,
            snapshot: Option<&transport::TransactionSnapshot>,
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
                profile.runtime_for(value.current, info.role)?;
                if let Some(requested) = value.requested {
                    profile.runtime_for(requested, info.role)?;
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
                carrier: match settings.cover.appearance {
                    l2tunnel_cover::Appearance::QuicLike => "quic-like",
                    l2tunnel_cover::Appearance::MediaLike => "media-like",
                }
                .into(),
                algorithm: "swift".into(),
                protection: "chacha20-poly1305".into(),
                backend: "generic_swift_v1".into(),
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
                send: snapshot
                    .map(|value| Direction::try_from(value.send))
                    .transpose()?,
                receive: snapshot
                    .map(|value| Direction::try_from(value.receive))
                    .transpose()?,
                storage: snapshot
                    .map(|value| Storage::try_from(value.storage))
                    .transpose()?,
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
                swift_unconfirmed: snapshot
                    .map(|value| number(value.swift_unconfirmed))
                    .transpose()?,
                configuration_change: true,
                coordinator: info.role == Role::Initiator,
                reconnect: true,
                cross_profile_switching: false,
                retained_state_recovery: false,
                fresh_rekey: false,
            })
        }
    }
}

#[cfg(test)]
#[path = "transaction_status_tests.rs"]
mod tests;

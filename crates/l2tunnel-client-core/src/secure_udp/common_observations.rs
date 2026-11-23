//! Portable Common runtime observations, independent of native runtime owners.
use l2tunnel_management::{self as mg, transaction};
use serde::{Deserialize, Serialize};

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

/// Counts of retained native packet admission attempts by the actual rejecting owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeIngressRefusals {
    /// The ACK coalescer could not retain another flow history.
    pub ack_history: u64,
    /// The packet flow assignment table was full.
    pub flow_table: u64,
    /// The pipeline shared byte allowance was full.
    pub shared_byte: u64,
    /// The pipeline shared packet allowance was full.
    pub shared_packet: u64,
    /// The selected TUN flow exhausted its byte allowance.
    pub flow_byte: u64,
    /// The selected TUN flow exhausted its packet allowance.
    pub flow_packet: u64,
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
    /// User input refused under native output pressure.
    pub backpressure_drops: u64,
    /// Capacity refusal attempts for the retained input. One packet can be retried repeatedly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_refusals: Option<NativeIngressRefusals>,
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

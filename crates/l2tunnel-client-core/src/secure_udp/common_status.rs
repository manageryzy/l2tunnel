//! Portable bounded version4 observations, independent of native runtime owners.

use l2tunnel::record_configuration::{CONFIGURATION_BYTES, Configuration};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{fmt, io};

#[path = "common_compact_status.rs"]
mod compact_wire;
pub use compact_wire::{
    CompactCheckCounts, CompactDataProtection, CompactWireSelection, CompactWireStatus,
};

#[path = "common_ack.rs"]
mod ack;
pub use ack::{AckObservation, AckPolicies, AckPolicy, AckRead, AckSelection, AckStatus};

/// Global source direction of a mixed-packet producer or consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StripedDirection {
    /// Traffic from the session initiator to the responder.
    InitiatorToResponder,
    /// Traffic from the session responder to the initiator.
    ResponderToInitiator,
}

/// Mixed group formation in one producer epoch, independent of datagram retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StripedFormation {
    /// Ordinary groups at the negotiated size.
    pub full_groups: u64,
    /// Shorter ordinary groups.
    pub short_groups: u64,
    /// Splits made with only one input at the original batch deadline.
    pub lone_splits: u64,
    /// Splits made with multiple inputs and no ordinary prefix fitting the MTU.
    pub mtu_splits: u64,
    /// Splits of a single input left after sealing part of a frozen batch.
    pub trailing_splits: u64,
    /// Number of first seals, counted once per input batch.
    pub batches: u64,
    /// Total time from oldest input to first seal across those batches.
    pub hold_micros: u64,
    /// Total time beyond the first input's deadline at first seal.
    pub late_micros: u64,
    /// Largest first-seal delay beyond that deadline.
    pub max_late_micros: u64,
}

/// IP charges supplied on complete carrier acceptance in the current mixed epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StripedPayments {
    /// First transmissions, including both members of every split.
    pub fresh: StripedCharge,
    /// Retries of explicitly named originals.
    pub named: StripedCharge,
    /// Quiet-tail retries.
    pub quiet: StripedCharge,
    /// Feedback for the opposite producer sent on this endpoint's carrier.
    pub feedback: StripedCharge,
}

/// Complete physical datagrams and the corresponding charged IP bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StripedCharge {
    /// Completed datagrams.
    pub packets: u64,
    /// IP bytes supplied at physical payment.
    pub ip_bytes: u64,
}

impl From<l2tunnel::fec::striped_group::schedule::Paid> for StripedCharge {
    fn from(paid: l2tunnel::fec::striped_group::schedule::Paid) -> Self {
        Self {
            packets: paid.packets,
            ip_bytes: paid.ip_bytes,
        }
    }
}

/// Exact source debt in the current mixed epoch, in logical source units.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StripedSources {
    /// Local producer's data direction.
    pub send_direction: StripedDirection,
    /// Authenticated stream of the producer.
    pub send_stream: u32,
    /// Assigned sources still awaiting peer confirmation.
    pub send_outstanding: u64,
    /// Source slots retained for physical recovery, including partial group custody.
    pub send_retained: u64,
    /// Absent in status captured before group formation accounting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_formation: Option<StripedFormation>,
    /// Absent in historical status captures without the per-class charges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_paid: Option<StripedPayments>,
    /// Last inclusive applied peer receipt.
    pub send_confirmed: Option<u64>,
    /// Local consumer's data direction.
    pub receive_direction: StripedDirection,
    /// Authenticated stream of the consumer.
    pub receive_stream: u32,
    /// Last contiguous native commit.
    pub receive_confirmed: Option<u64>,
    /// First source outside the confirmed prefix.
    pub receive_frontier: Option<u64>,
    /// Last ID known to have been sealed by the peer.
    pub receive_sealed: Option<u64>,
    /// Pending native commits in admitted groups.
    pub receive_uncommitted_in_groups: u64,
    /// Pending native commits including unseen gaps through the sealed horizon.
    pub receive_uncommitted_through_sealed: u64,
}

impl From<l2tunnel::striped_records::SourceStatus> for StripedSources {
    fn from(v: l2tunnel::striped_records::SourceStatus) -> Self {
        use StripedDirection::{InitiatorToResponder, ResponderToInitiator};
        let (send_direction, receive_direction) = match v.send_direction {
            l2tunnel::fec::Direction::ClientToServer => {
                (InitiatorToResponder, ResponderToInitiator)
            }
            l2tunnel::fec::Direction::ServerToClient => {
                (ResponderToInitiator, InitiatorToResponder)
            }
        };
        Self {
            send_direction,
            send_stream: v.send_stream,
            send_outstanding: v.send_outstanding as u64,
            send_retained: v.send_retained as u64,
            send_formation: Some(StripedFormation {
                full_groups: v.send_formation.full_groups,
                short_groups: v.send_formation.short_groups,
                lone_splits: v.send_formation.lone_splits,
                mtu_splits: v.send_formation.mtu_splits,
                trailing_splits: v.send_formation.trailing_splits,
                batches: v.send_formation.batches,
                hold_micros: v.send_formation.hold_ticks,
                late_micros: v.send_formation.late_ticks,
                max_late_micros: v.send_formation.max_late_ticks,
            }),
            send_paid: Some(StripedPayments {
                fresh: v.send_paid.fresh.into(),
                named: v.send_paid.named.into(),
                quiet: v.send_paid.quiet.into(),
                feedback: v.feedback_paid.into(),
            }),
            send_confirmed: v.send_confirmed.map(|id| id.0),
            receive_direction,
            receive_stream: v.receive_stream,
            receive_confirmed: v.receive_confirmed.map(|id| id.0),
            receive_frontier: v.receive_frontier.map(|id| id.0),
            receive_sealed: v.receive_sealed.map(|id| id.0),
            receive_uncommitted_in_groups: v.receive_uncommitted_in_groups as u64,
            receive_uncommitted_through_sealed: v.receive_uncommitted_through_sealed as u64,
        }
    }
}

#[path = "common_rolling_ingress.rs"]
mod rolling_ingress;
pub use rolling_ingress::{
    RollingIngressLimits, RollingIngressObservation, RollingIngressPolicies, RollingIngressStatus,
};

/// Selected source and repair grammar of one authenticated global direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollingWireProfile {
    /// Padded originals.
    Padded,
    /// Exact originals, with ordinary recovery feedback.
    Exact,
    /// Exact originals and targeted C48 recovery.
    TargetedExact,
    /// Targeted C48 recovery with forward eight-source equations.
    TargetedNear8,
    /// Forward near8 with bounded native TCP reordering at the receiver.
    TargetedNear8Hold35,
    /// Forward near8 with confirmed-prefix global repair.
    TargetedNear8ConfirmedPrefix,
    /// Forward near8 with an additional repair paid from unused source credit.
    TargetedNear8Headroom,
    /// Targeted exact recovery with optional compression of packed ACK sources.
    TargetedExactAckLz4,
}

impl From<l2tunnel::fec::rolling::wire::SourceWire> for RollingWireProfile {
    fn from(wire: l2tunnel::fec::rolling::wire::SourceWire) -> Self {
        use l2tunnel::fec::rolling::wire::SourceWire;
        match wire {
            SourceWire::Padded => Self::Padded,
            SourceWire::Exact => Self::Exact,
            SourceWire::TargetedExact => Self::TargetedExact,
            SourceWire::TargetedNear8 => Self::TargetedNear8,
            SourceWire::TargetedNear8Hold35 => Self::TargetedNear8Hold35,
            SourceWire::TargetedNear8ConfirmedPrefix => Self::TargetedNear8ConfirmedPrefix,
            SourceWire::TargetedNear8Headroom => Self::TargetedNear8Headroom,
            SourceWire::TargetedExactAckLz4 => Self::TargetedExactAckLz4,
        }
    }
}

/// The globally ordered C48 wire selection, identical at both peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollingWireDirections {
    /// Client-to-server grammar.
    pub forward: RollingWireProfile,
    /// Server-to-client grammar.
    pub reverse: RollingWireProfile,
}
impl RollingWireDirections {
    pub(crate) fn from_descriptor(
        value: &l2tunnel::record_configuration::Descriptor,
    ) -> Option<Self> {
        use l2tunnel::record_configuration::Profile;
        match value.profile() {
            Profile::Rolling { config, .. } | Profile::RollingCopies { config, .. } => Some(Self {
                forward: config.forward.scheduler.source_wire.into(),
                reverse: config.reverse.scheduler.source_wire.into(),
            }),
            _ => None,
        }
    }
}

/// Original request, in-flight proposal and installed rolling grammar of the active epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollingWireProfiles {
    /// Initial selection in the original pre-establishment catalog.
    pub initial_requested: Option<RollingWireDirections>,
    /// Candidate tracked by the transaction owner, when it is a rolling profile.
    pub pending: Option<RollingWireDirections>,
    /// Current rolling selection reported by the authenticated live owner.
    pub effective: Option<RollingWireDirections>,
}

/// Observed capacity decisions for the selected eight-source profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Near8GateCounts {
    /// Intervals that could not be evaluated, including skipped intervals.
    pub partial_buckets: u64,
    /// Complete observed intervals with no physically accepted bytes.
    pub empty_buckets: u64,
    /// Complete nonempty intervals at or below 75 percent of the pacing budget.
    pub light_buckets: u64,
    /// Complete intervals above 75 and below 90 percent of the pacing budget.
    pub middle_buckets: u64,
    /// Complete intervals at or above 90 percent of the pacing budget.
    pub busy_buckets: u64,
    /// Complete intervals over the aggregate ordinary backlog threshold, across utilization bands.
    pub backlogged_buckets: u64,
    /// Boundary decisions that left the gate open for the following interval.
    pub open_buckets: u64,
    /// Gated groups lacking a capacity sample for the current interval.
    pub stale_groups: u64,
    /// Gated groups observed while the sustained gate was closed.
    pub closed_groups: u64,
    /// Gated groups above the instantaneous aggregate threshold, including when closed.
    pub backlogged_groups: u64,
}

/// Additional near8 repair funded by original credit above the ordinary cap.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Near8HeadroomBudget {
    /// Available extra credit in eighths of one IP byte.
    pub credit_eighths: u64,
    /// Groups considered for an additional row.
    pub qualifying_groups: u64,
    /// Groups withheld for insufficient credit.
    pub unfunded: u64,
    /// Groups withheld by physical link load.
    pub wire_busy: u64,
    /// Additional rows abandoned before submission.
    pub abandoned: u64,
    /// Additional rows accepted by the carrier.
    pub sent_rows: u64,
    /// Complete physical IP bytes charged for these rows.
    pub sent_ip_bytes: u64,
}

/// Independent eight-source repair budget observed at local physical handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Near8Budget {
    /// Present when the authenticated profile selects overflow-funded repair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headroom: Option<Near8HeadroomBudget>,
    /// Sustained spare-capacity gate.
    pub spare: bool,
    /// Independent counters for the observed reasons at each decision.
    #[serde(default)]
    pub gate: Near8GateCounts,
    /// Non-overlapping, completed first-copy groups.
    pub opportunities: u64,
    /// Groups withheld by capacity, credit, MTU or pre-handoff cancellation.
    pub gated: u64,
    /// Groups without sufficient credit.
    pub unfunded: u64,
    /// Groups too large for one carrier datagram.
    pub oversized: u64,
    /// Unexposed rows abandoned under pressure or expiry.
    pub abandoned: u64,
    /// Rows physically accepted.
    pub sent_rows: u64,
    /// Actual accepted complete-IP cost.
    pub sent_ip_bytes: u64,
    /// Global or tail rows confirmed at physical handoff.
    #[serde(default)]
    pub global_sent_rows: u64,
    /// Confirmed global rows with a shorter than nominal support.
    #[serde(default)]
    pub global_trimmed_rows: u64,
    /// Nominal source columns across confirmed global rows, including startup ramps.
    #[serde(default)]
    pub global_nominal_columns: u64,
    /// Actual covered source columns in those rows.
    #[serde(default)]
    pub global_sent_columns: u64,
    /// Remaining physical-byte credit in eighths of one byte.
    pub credit_eighths: u64,
}
/// Receiver-side authenticated TCP native hold counters in the active generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollingNativeReorder {
    /// First ahead-of-prefix segment starting a new hold.
    pub starts: u64,
    /// Episodes released at the original soft deadline.
    pub deadline_releases: u64,
    /// Episodes released upon exceeding the permitted byte span.
    pub span_releases: u64,
    /// Ahead-of-prefix data packets physically accepted during bypass.
    pub bypass_writes: u64,
    /// Waiting episodes closed by physical writes before bypass.
    pub prefix_closes: u64,
    /// Released episodes whose contiguous edge reached the original barrier.
    pub bypass_prefix_closes: u64,
    /// Flows failing open when the bounded exact range ledger fills.
    pub range_overflows: u64,
}
impl From<l2tunnel::rolling_records::NativeReorderStatus> for RollingNativeReorder {
    fn from(value: l2tunnel::rolling_records::NativeReorderStatus) -> Self {
        Self {
            starts: value.starts,
            deadline_releases: value.deadline_releases,
            span_releases: value.span_releases,
            bypass_writes: value.bypass_writes,
            prefix_closes: value.prefix_closes,
            bypass_prefix_closes: value.bypass_prefix_closes,
            range_overflows: value.range_overflows,
        }
    }
}

/// Requested or effective native release order at the local receiver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollingRelease {
    /// Resolved per direction; see the effective value.
    Default,
    /// Channel record order without per-flow tracking.
    Channel,
    /// Ethernet TCP data in flow order.
    EthernetFlowOrdered,
    /// Authenticated bounded native hold.
    BoundedHold,
    /// IP TCP data released across sequence gaps.
    Independent,
    /// IP TCP data released only in its flow's order.
    FlowOrdered,
}
impl From<l2tunnel::rolling_records::NativeRelease> for RollingRelease {
    fn from(value: l2tunnel::rolling_records::NativeRelease) -> Self {
        use l2tunnel::rolling_records::NativeRelease;
        match value {
            NativeRelease::Default => Self::Default,
            NativeRelease::Independent => Self::Independent,
            NativeRelease::FlowOrdered => Self::FlowOrdered,
        }
    }
}
impl From<l2tunnel::rolling_records::EffectiveRelease> for RollingRelease {
    fn from(value: l2tunnel::rolling_records::EffectiveRelease) -> Self {
        use l2tunnel::rolling_records::EffectiveRelease;
        match value {
            EffectiveRelease::Channel => Self::Channel,
            EffectiveRelease::EthernetFlowOrdered => Self::EthernetFlowOrdered,
            EffectiveRelease::BoundedHold => Self::BoundedHold,
            EffectiveRelease::Independent => Self::Independent,
            EffectiveRelease::FlowOrdered => Self::FlowOrdered,
        }
    }
}
/// Requested return-guard mode of the local sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollingGuardMode {
    /// Resolved per direction; see the effective ratio.
    Default,
    /// Measure only.
    Off,
    /// Shed above the requested ratio.
    On,
}
/// Requested/effective release order and local return guard in the active generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollingDelivery {
    /// Requested receive-direction release.
    pub requested_release: RollingRelease,
    /// Effective receive-direction release.
    pub effective_release: RollingRelease,
    /// Requested send-direction guard mode.
    pub requested_guard: RollingGuardMode,
    /// Requested ratio per thousand; zero unless the mode is on.
    pub requested_guard_per_mille: u16,
    /// Effective ratio per thousand; absent when the guard only measures.
    pub effective_guard_per_mille: Option<u16>,
    /// Whether the guard is currently engaged as a return path.
    pub guard_engaged: bool,
    /// One-second window: native bytes delivered from the peer.
    pub window_delivered_bytes: u64,
    /// One-second window: first-copy wire bytes sent.
    pub window_first_bytes: u64,
    /// One-second window: never-shed wire bytes sent.
    pub window_required_bytes: u64,
    /// One-second window: sheddable extra wire bytes sent.
    pub window_extra_bytes: u64,
    /// Sources admitted with their extra copies removed.
    pub shed_copy_sources: u64,
    /// Estimated wire bytes of removed copies.
    pub shed_copy_bytes: u64,
    /// Regular repairs displaced by the guard.
    pub shed_repairs: u64,
    /// Estimated wire bytes of displaced repairs.
    pub shed_repair_bytes: u64,
}
impl From<l2tunnel::rolling_records::DeliveryStatus> for RollingDelivery {
    fn from(value: l2tunnel::rolling_records::DeliveryStatus) -> Self {
        use l2tunnel::rolling_records::GuardMode;
        let g = value.guard;
        Self {
            requested_release: value.requested_release.into(),
            effective_release: value.effective_release.into(),
            requested_guard: match g.requested.mode {
                GuardMode::Default => RollingGuardMode::Default,
                GuardMode::Off => RollingGuardMode::Off,
                GuardMode::On => RollingGuardMode::On,
            },
            requested_guard_per_mille: g.requested.per_mille,
            effective_guard_per_mille: g.effective_per_mille,
            guard_engaged: g.engaged,
            window_delivered_bytes: g.window_delivered_bytes,
            window_first_bytes: g.window_first_bytes,
            window_required_bytes: g.window_required_bytes,
            window_extra_bytes: g.window_extra_bytes,
            shed_copy_sources: g.shed_copy_sources,
            shed_copy_bytes: g.shed_copy_bytes,
            shed_repairs: g.shed_repairs,
            shed_repair_bytes: g.shed_repair_bytes,
        }
    }
}

/// Physical retransmission credits and regular FEC spending in the active local sender.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollingRepairBudget {
    /// Present only for the selected near8 sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near8: Option<Near8Budget>,
    /// Named source requests observed by the sender, when reported by this service.
    pub named_requests: Option<RollingNamedRequests>,
    /// Remaining and maximum credit, expressed in half-bytes.
    pub balance_half_bytes: u64,
    /// Selected 32-MTU credit ceiling, in half-bytes.
    pub cap_half_bytes: u64,
    /// Accepted named retries that earned half their physical cost.
    pub half_weight_retries: u64,
    /// Accepted named retries that earned their full physical cost.
    pub full_weight_retries: u64,
    /// Opportunities to send a regular equation.
    pub regular_opportunities: u64,
    /// Number of whole proactive equations displaced.
    pub displaced_repairs: u64,
    /// Sum of prospectively avoided physical IP bytes.
    pub displaced_wire_bytes: u64,
    /// Actual physical wire bytes of accepted solicited retransmissions.
    pub requested_retry_wire_bytes: u64,
    /// Accepted quiet probes of the oldest retained original.
    pub quiet_probes: u64,
    /// Actual physical wire bytes of accepted quiet probes.
    pub quiet_probe_wire_bytes: u64,
    /// Actual physical wire bytes of accepted proactive repairs.
    pub regular_wire_bytes: u64,
    /// Actual physical wire bytes of accepted extra configured source copies.
    pub copy_wire_bytes: u64,
    /// Originals retained beyond the authenticated cumulative prefix.
    pub unconfirmed_sources: u32,
    /// Fresh originals waiting for encoder service.
    #[serde(default)]
    pub queued_fresh: usize,
    /// Largest number of fresh originals simultaneously waiting for service.
    #[serde(default)]
    pub peak_queued_fresh: usize,
    /// Maximum number of fresh originals admitted ahead of service.
    #[serde(default)]
    pub fresh_queue_limit: usize,
    /// Credit earned before saturation, in half-bytes.
    pub earned_half_bytes: u64,
    /// Credit above the fixed cap, in half-bytes.
    pub capped_half_bytes: u64,
    /// Residual credit expired on full confirmation, in half-bytes.
    pub expired_half_bytes: u64,
    /// Prospective total physical bytes of regular opportunities.
    pub opportunity_wire_bytes: u64,
    /// Current hysteresis state of this local sender.
    pub full_credit: bool,
}

/// Distinct source request identities and their disposition under local backpressure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RollingNamedRequests {
    /// First request for a source still retained.
    pub first: u64,
    /// Newer request serials for a previously requested source.
    pub repeated: u64,
    /// Repeated requests coalesced before their retry was selected.
    pub coalesced_queued: u64,
    /// Repeated requests coalesced after preparation and before physical handoff.
    pub coalesced_prepared: u64,
    /// Previously observed or older request serials for the same source.
    pub duplicate_or_older: u64,
    /// Named sources already cumulatively confirmed.
    pub confirmed: u64,
}
impl From<l2tunnel::rolling_records::RepairBudgetStatus> for RollingRepairBudget {
    fn from(s: l2tunnel::rolling_records::RepairBudgetStatus) -> Self {
        Self {
            near8: s.near8.map(|v| Near8Budget {
                headroom: v.headroom.map(|h| Near8HeadroomBudget {
                    credit_eighths: h.credit_eighths,
                    qualifying_groups: h.qualifying_groups,
                    unfunded: h.unfunded,
                    wire_busy: h.wire_busy,
                    abandoned: h.abandoned,
                    sent_rows: h.sent_rows,
                    sent_ip_bytes: h.sent_ip_bytes,
                }),
                spare: v.spare,
                gate: Near8GateCounts {
                    partial_buckets: v.gate.partial_buckets,
                    empty_buckets: v.gate.empty_buckets,
                    light_buckets: v.gate.light_buckets,
                    middle_buckets: v.gate.middle_buckets,
                    busy_buckets: v.gate.busy_buckets,
                    backlogged_buckets: v.gate.backlogged_buckets,
                    open_buckets: v.gate.open_buckets,
                    stale_groups: v.gate.stale_groups,
                    closed_groups: v.gate.closed_groups,
                    backlogged_groups: v.gate.backlogged_groups,
                },
                opportunities: v.opportunities,
                gated: v.gated,
                unfunded: v.unfunded,
                oversized: v.oversized,
                abandoned: v.abandoned,
                sent_rows: v.sent_rows,
                sent_ip_bytes: v.sent_ip_bytes,
                global_sent_rows: v.global_sent_rows,
                global_trimmed_rows: v.global_trimmed_rows,
                global_nominal_columns: v.global_nominal_columns,
                global_sent_columns: v.global_sent_columns,
                credit_eighths: v.credit_eighths,
            }),
            named_requests: Some(RollingNamedRequests {
                first: s.named_requests.first,
                repeated: s.named_requests.repeated,
                coalesced_queued: s.named_requests.coalesced_queued,
                coalesced_prepared: s.named_requests.coalesced_prepared,
                duplicate_or_older: s.named_requests.duplicate_or_older,
                confirmed: s.named_requests.confirmed,
            }),
            balance_half_bytes: s.balance_half_bytes,
            cap_half_bytes: s.cap_half_bytes,
            half_weight_retries: s.half_weight_retries,
            full_weight_retries: s.full_weight_retries,
            regular_opportunities: s.regular_opportunities,
            displaced_repairs: s.displaced_repairs,
            displaced_wire_bytes: s.displaced_wire_bytes,
            requested_retry_wire_bytes: s.requested_retry_wire_bytes,
            quiet_probes: s.quiet_probes,
            quiet_probe_wire_bytes: s.quiet_probe_wire_bytes,
            regular_wire_bytes: s.regular_wire_bytes,
            copy_wire_bytes: s.copy_wire_bytes,
            unconfirmed_sources: s.unconfirmed_sources,
            queued_fresh: s.queued_fresh,
            peak_queued_fresh: s.peak_queued_fresh,
            fresh_queue_limit: s.fresh_queue_limit,
            earned_half_bytes: s.earned_half_bytes,
            capped_half_bytes: s.capped_half_bytes,
            expired_half_bytes: s.expired_half_bytes,
            opportunity_wire_bytes: s.opportunity_wire_bytes,
            full_credit: s.full_credit,
        }
    }
}

#[path = "common_maintained_status.rs"]
mod maintained;
#[path = "common_raw_status.rs"]
mod raw;
pub use maintained::{
    MaintainedCarrier, MaintainedLane, MaintainedPolicy, QuicQueues, TlsQueueAvailability,
    TlsSendQueue,
};
pub use raw::{RawCarrier, RawFinalFraming, RawLane, RawLaneLimits, RawPacketPolicy};

#[path = "common_connection_status.rs"]
mod connections;
pub use connections::{
    ConnectionIngressLimits, ConnectionIngressObservation, ConnectionIngressPolicies,
    ConnectionIngressStatus, ConnectionRecovery,
};

#[path = "common_fragment_status.rs"]
mod fragments;
pub use fragments::{
    FragmentCounters, FragmentDirection, FragmentFraming, FragmentIngress, FragmentReassembly,
    FragmentStatus, ReassemblyLimits, RollingFragments,
};

#[path = "common_reuse_status.rs"]
mod reuse;
pub use reuse::{
    ConnectionReuseConfirmation, ConnectionReuseOperation, ConnectionReuseOutcome,
    ConnectionReusePhase, ConnectionReuseResult, ConnectionReuseStatus,
};

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
#[path = "common_observations.rs"]
mod observations;
pub use observations::{
    Control, Liveness, Native, NativeIngressRefusals, Operation, Phase, Scope, Security, Storage,
    Wire,
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
/// Genuine original-carrier proof and the requested/effective Common bindings.
/// These public values carry no credential, socket or authentication authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalCarrier {
    /// Explicit requested outer protocol.
    pub requested: String,
    /// Outer protocol that actually completed authentication.
    pub effective: String,
    /// Independently selected layout inside the outer carrier.
    pub udp_cover: String,
    /// Original offline Common configuration before the fresh outer proof.
    pub requested_configuration: [u8; 32],
    /// Original offline Common envelope E0.
    pub requested_envelope: [u8; 32],
    /// Original catalog before the selected carrier's explicit framing overhead.
    pub requested_catalog: [u8; 32],
    /// Actual Common configuration bound to this authenticated outer session.
    pub effective_configuration: [u8; 32],
    /// Actual Common envelope E1, also used by the complete runtime catalog.
    pub effective_envelope: [u8; 32],
    /// Actual catalog with the selected carrier's exact framing overhead.
    pub effective_catalog: [u8; 32],
    /// Actual nonsecret TLS/member session identity.
    pub session: [u8; 16],
    /// Complete authenticated outer policy digest.
    pub configuration: [u8; 32],
    /// Original-socket outer proof committed by the inner Noise prologue.
    pub binding: [u8; 32],
    /// Exact requested complete outer IP packet ceiling.
    pub path_mtu: u64,
    /// Exact requested opaque record capacity, excluding the outer opcode.
    pub max_record_bytes: u64,
    /// Explicit outer session-age policy, independent of any key refresh.
    pub lifetime_nanos: u64,
    /// Original reset/TLS/member establishment bound.
    pub handshake_timeout_nanos: u64,
}
/// Same-flow UDP observations; not authentication or peer-state reconciliation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRecovery {
    /// Actual local admission pause pending fresh protected peer input.
    pub unavailable: bool,
    /// Actual selected pre-accept send errors, including failed retries.
    pub send_failures: u64,
    /// Actual retained User send attempts while already unavailable.
    pub retry_attempts: u64,
    /// Actual fresh same-session protected receipts restoring availability.
    pub resumptions: u64,
    /// Bounded local I/O category, without peer text or credentials.
    pub last_error: Option<String>,
    /// Original Driver clock time for the next retained User attempt.
    pub retry_at_micros: Option<u64>,
}
/// Actual native-delivery credit for one current or draining Common epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDelivery {
    /// Exact negotiated epoch owning these counters.
    pub epoch: u64,
    /// Exact complete configuration digest for this owner.
    pub configuration: [u8; 32],
    /// Actual original-native admission, carrier acceptance and peer-device delivery.
    pub send: Option<crate::raw_packet::NativeFlight>,
    /// A real local native write awaits reliable control admission.
    pub pending_receipt: bool,
}
impl From<l2tunnel_runtime::secure_udp::transport::NativeDeliverySnapshot> for NativeDelivery {
    fn from(value: l2tunnel_runtime::secure_udp::transport::NativeDeliverySnapshot) -> Self {
        Self {
            epoch: value.epoch,
            configuration: value.configuration.0,
            send: value.send.map(Into::into),
            pending_receipt: value.pending_receipt,
        }
    }
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
    /// Present only after the original outer carrier actually authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_carrier: Option<OriginalCarrier>,
    /// Present only after the actual original raw TCP carrier authenticates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_carrier: Option<RawCarrier>,
    /// Explicit maintained request and actual Driver observations; absent for legacy carriers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintained_carrier: Option<Box<MaintainedCarrier>>,
    /// Data algorithm, separate from carrier selection.
    pub algorithm: String,
    /// Actual required integrity/confidentiality profile.
    pub protection: String,
    /// Explicit compact request and actual installed state; absent for legacy bytes.
    /// Heap-held so this optional observation does not inflate legacy response futures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact_wire: Option<Box<CompactWireStatus>>,
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
    /// Exact requested startup KCP-like policy, absent for other algorithms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcp_like_initial: Option<serde_json::Value>,
    /// Actual current KCP-like policy, absent before installation or for other algorithms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcp_like_current: Option<serde_json::Value>,
    /// Retained switch request, never substituted for the effective policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kcp_like_requested: Option<serde_json::Value>,
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
    /// Actual current/draining NativeWindow owners; absent before runtime observation.
    #[serde(default)]
    pub native_delivery: [Option<NativeDelivery>; 2],
    /// Actual fixed control retained custody.
    pub control: Option<Control>,
    /// Actual nonsecret outgoing security identifiers.
    pub security: Option<Security>,
    /// Actual fixed-scope authenticated challenge state.
    pub liveness: Option<Liveness>,
    /// Same original UDP flow only; full retained-state recovery stays unqualified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_recovery: Option<PathRecovery>,
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
    /// Requested, pending and effective rolling wire names in global direction order.
    #[serde(default)]
    pub rolling_wire_profiles: RollingWireProfiles,
    /// Observed only when the active descriptor selects targeted recovery locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_repair_budget: Option<RollingRepairBudget>,
    /// Observed only from an active mixed-packet owner in this epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub striped_sources: Option<StripedSources>,
    /// Effective bounded native TCP hold observations, absent on the ordinary receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_native_reorder: Option<RollingNativeReorder>,
    /// Requested/effective release order and return guard of the active rolling generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_delivery: Option<RollingDelivery>,
    /// Explicit immutable Benchmark policy and actual Engine ingress observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_coalescing: Option<AckStatus>,
    /// Establishment-bound input selection and actual current Rolling Queue state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_ingress: Option<RollingIngressStatus>,
    /// Paired raw ACK ingress policy and actual queue observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_ingress: Option<ConnectionIngressStatus>,
    /// Actual independent recovery cohort, absent for other active profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections: Option<ConnectionRecovery>,
    /// Explicit negotiated flow-reuse selection and actual controller/capability facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_reuse: Option<Box<ConnectionReuseStatus>>,
    /// Retained keyed reuse completion, independent of the current selection/generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_reuse_result: Option<Box<ConnectionReuseResult>>,
    /// Complete fragment request and actual current Engine selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rolling_fragments: Option<FragmentStatus>,
    /// Actual directional scheduler step count, never inferred from packet count.
    pub rolling_scheduler_steps: Option<u64>,
    /// Actual cumulative GF/copy/metadata work consumed.
    pub rolling_work_used: Option<[u64; 3]>,
    /// Original UDP read batches yielded for an active decoder at queue pressure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_rolling_pressure_yields: Option<u64>,
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
            let effective = profile.establish_config(info.role)?;
            let expected = if let Some(outer) = profile.maintained_binding() {
                outer.expected_binding(effective, profile.peers(), info.binding.session)
            } else {
                match (profile.carrier_binding(), profile.raw_binding()) {
                    (Some(outer), None) => {
                        outer.expected_binding(effective, profile.peers(), info.binding.session)
                    }
                    (None, Some(outer)) => {
                        outer.expected_binding(effective, profile.peers(), info.binding.session)
                    }
                    (None, None) => {
                        effective.expected_binding(profile.peers(), info.binding.session)
                    }
                    (Some(_), Some(_)) => {
                        return Err(invalid("conflicting original carrier bindings"));
                    }
                }
            }
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
                || snapshot.is_some_and(|value| {
                    value.info != info
                        || value.configuration != configuration
                        || value.compact_wire != Some(profile.compact_wire())
                })
            {
                return Err(invalid(
                    "transaction observation differs from retained authenticated plan",
                ));
            }
            let requested_ack = AckPolicies::from_policies(profile.ack_coalescing())?;
            let requested_rolling =
                RollingIngressPolicies::from_policies(profile.rolling_ingress())?;
            let effective_resources = profile.runtime_contract(info.role)?.resources();
            let expected_rolling = effective_resources.rolling_ingress;
            if let Some(value) = snapshot {
                let expected_fragments = if matches!(
                    value.current.descriptor().profile(),
                    l2tunnel::record_configuration::Profile::Rolling { .. }
                        | l2tunnel::record_configuration::Profile::RollingCopies { .. }
                        | l2tunnel::record_configuration::Profile::Research { .. }
                ) {
                    effective_resources.rolling_fragments
                } else {
                    None
                };
                if value.rolling_fragments != expected_fragments {
                    return Err(invalid(
                        "actual fragment selection differs from authenticated effective policy",
                    ));
                }
            }
            if snapshot.is_some_and(|value| {
                value.rolling_ingress != expected_rolling
                    || value
                        .rolling_input
                        .is_some_and(|input| Some(input.limits) != expected_rolling)
                    || matches!(
                        value.current.descriptor().profile(),
                        l2tunnel::record_configuration::Profile::Rolling { .. }
                            | l2tunnel::record_configuration::Profile::RollingCopies { .. }
                            | l2tunnel::record_configuration::Profile::Research { .. }
                    ) && value.rolling_input.map(|input| input.limits) != expected_rolling
            }) {
                return Err(invalid(
                    "actual coded ingress differs from authenticated policy",
                ));
            }
            let requested_connections =
                ConnectionIngressPolicies::from_policies(profile.connection_ingress())?;
            let expected_connections = profile
                .runtime_contract(info.role)?
                .resources()
                .connection_ingress;
            if snapshot.is_some_and(|value| {
                value.connection_input.map(|input| input.limits) != expected_connections
            }) {
                return Err(invalid(
                    "actual raw ACK ingress differs from authenticated policy",
                ));
            }
            let expected_ack = profile
                .runtime_contract(info.role)?
                .resources()
                .ack_coalescing;
            if snapshot.is_some_and(|value| {
                value.ack_ingress.map(|ingress| ingress.policy) != expected_ack
            }) {
                return Err(invalid(
                    "actual ACK ingress differs from retained authenticated policy",
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
            let udp_cover = match settings.cover.appearance {
                l2tunnel_cover::Appearance::QuicLike => "quic-like",
                l2tunnel_cover::Appearance::MediaLike => "media-like",
            };
            let original_carrier = profile
                .carrier_binding()
                .map(|outer| {
                    Ok::<_, io::Error>(OriginalCarrier {
                        requested: "openvpn-like".into(),
                        effective: "openvpn-like".into(),
                        udp_cover: udp_cover.into(),
                        requested_configuration: profile.requested_configuration()?.0,
                        requested_envelope: *profile.requested_envelope().as_bytes(),
                        requested_catalog: *profile.requested_catalog().root().as_bytes(),
                        effective_configuration: configuration.0,
                        effective_envelope: *profile.envelope().as_bytes(),
                        effective_catalog: *profile.catalog().root().as_bytes(),
                        session: outer.info().session_id,
                        configuration: outer.info().config.digest.0,
                        binding: outer.binding(),
                        path_mtu: number(outer.requested().path_mtu)?,
                        max_record_bytes: number(outer.requested().max_record_bytes)?,
                        lifetime_nanos: u64::try_from(outer.requested().lifetime.as_nanos())
                            .map_err(invalid)?,
                        handshake_timeout_nanos: u64::try_from(
                            outer.requested().handshake_timeout.as_nanos(),
                        )
                        .map_err(invalid)?,
                    })
                })
                .transpose()?;
            let raw_carrier = RawCarrier::observe(profile, configuration, udp_cover, snapshot)?;
            let maintained_carrier = MaintainedCarrier::observe(profile, snapshot)?.map(Box::new);
            Ok(Self {
                generation,
                next_request_key: None,
                carrier: if let Some(value) = &maintained_carrier {
                    &value.requested.carrier
                } else if raw_carrier.is_some() {
                    "raw-packet"
                } else if original_carrier.is_some() {
                    "openvpn-like"
                } else {
                    udp_cover
                }
                .into(),
                original_carrier,
                raw_carrier,
                maintained_carrier,
                algorithm: "common-records".into(),
                protection: CompactWireSelection::from_selection(profile.compact_wire())?
                    .data_protection
                    .name()
                    .into(),
                compact_wire: Some(Box::new(CompactWireStatus::observe(
                    profile.compact_wire(),
                    snapshot,
                )?)),
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
                kcp_like_initial: crate::kcp_like_l2::selected(
                    &profile.requested_catalog().initial(),
                ),
                kcp_like_current: snapshot
                    .and_then(|value| crate::kcp_like_l2::selected(value.current.descriptor())),
                kcp_like_requested: snapshot
                    .and_then(|value| value.requested)
                    .and_then(|value| crate::kcp_like_l2::selected(value.descriptor())),
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
                native_delivery: snapshot.map_or([None, None], |value| {
                    value.native_delivery.map(|owner| owner.map(Into::into))
                }),
                native: counters
                    .map(|value| {
                        Ok::<_, io::Error>(Native {
                            read: value.native_read,
                            written: value.native_written,
                            oversize: value.native_oversize,
                            backpressure_drops: value.native_backpressure_drops,
                            ingress_refusals: snapshot.map(|s| NativeIngressRefusals {
                                ack_history: s.performance.native_ingress_ack_history_refusals,
                                flow_table: s.performance.native_ingress_flow_table_refusals,
                                shared_byte: s.performance.native_ingress_shared_byte_refusals,
                                shared_packet: s.performance.native_ingress_shared_packet_refusals,
                                flow_byte: s.performance.native_ingress_flow_byte_refusals,
                                flow_packet: s.performance.native_ingress_flow_packet_refusals,
                            }),
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
                path_recovery: snapshot.map(|value| PathRecovery {
                    unavailable: value.path_recovery.unavailable,
                    send_failures: value.path_recovery.send_failures,
                    retry_attempts: value.path_recovery.retry_attempts,
                    resumptions: value.path_recovery.resumptions,
                    last_error: value
                        .path_recovery
                        .last_error
                        .map(|kind| format!("{kind:?}")),
                    retry_at_micros: value.path_recovery.retry_at_micros,
                }),
                configuration_change: true,
                coordinator: info.role == Role::Initiator,
                reconnect: true,
                cross_profile_switching: true,
                retained_state_recovery: false,
                fresh_rekey: false,
                rolling_wire_profiles: RollingWireProfiles {
                    initial_requested: RollingWireDirections::from_descriptor(
                        &profile.requested_catalog().initial(),
                    ),
                    pending: snapshot
                        .and_then(|value| value.requested)
                        .and_then(|configuration| {
                            RollingWireDirections::from_descriptor(configuration.descriptor())
                        }),
                    effective: snapshot.and_then(|value| {
                        RollingWireDirections::from_descriptor(value.current.descriptor())
                    }),
                },
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
                ack_coalescing: requested_ack
                    .map(|requested| AckStatus::observe(requested, snapshot))
                    .transpose()?,
                rolling_native_reorder: snapshot
                    .and_then(|s| s.rolling_native_reorder)
                    .map(Into::into),
                rolling_delivery: snapshot.and_then(|s| s.rolling_delivery).map(Into::into),
                rolling_repair_budget: snapshot
                    .and_then(|s| s.rolling_repair_budget)
                    .map(Into::into),
                striped_sources: snapshot.and_then(|s| s.striped_sources).map(Into::into),
                rolling_ingress: requested_rolling
                    .map(|requested| RollingIngressStatus::observe(requested, snapshot))
                    .transpose()?,
                connection_ingress: requested_connections
                    .map(|requested| {
                        ConnectionIngressStatus::observe(
                            requested,
                            snapshot.and_then(|v| v.connection_input),
                        )
                    })
                    .transpose()?,
                connections: snapshot
                    .and_then(|v| v.connections)
                    .map(ConnectionRecovery::observe),
                connection_reuse: ConnectionReuseStatus::observe(profile, info, snapshot)?
                    .map(Box::new),
                connection_reuse_result: None,
                rolling_fragments: profile
                    .rolling_fragments()
                    .map(|requested| FragmentStatus::observe(requested, snapshot))
                    .transpose()?,
                rolling_scheduler_steps: snapshot.map(|value| value.rolling_scheduler_steps),
                rolling_work_used: snapshot.map(|value| value.rolling_work_used),
                udp_rolling_pressure_yields: snapshot
                    .map(|value| value.performance.udp_rolling_pressure_yields),
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

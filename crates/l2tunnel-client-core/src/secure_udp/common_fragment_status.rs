//! Complete portable selected fragment policy and actual generation observations.
use super::*;
use l2tunnel::{codec, record_engine as engine};

/// Exact immutable global fragmentation selection, separate from record geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingFragments {
    /// Explicit policy schema version.
    pub version: u8,
    /// Initiator-to-responder complete policy.
    pub forward: FragmentDirection,
    /// Responder-to-initiator complete policy.
    pub reverse: FragmentDirection,
}
/// Complete direction, including all three independent reassembly owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentDirection {
    /// Exact physical geometry; no MTU adjustment or hidden defaults.
    pub framing: FragmentFraming,
    /// Exact bounds for each authenticated record kind.
    pub reassembly: FragmentReassembly,
    /// Distinct systematic, repair and feedback wire labels, not authority.
    pub labels: [u64; 3],
    /// Initial nonwrapping message identity for each actual Fragmenter.
    pub first_message: u64,
}
/// The three actual reassembly policies remain independently bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentReassembly {
    /// Systematic source limits.
    pub systematic: ReassemblyLimits,
    /// Repair limits.
    pub repair: ReassemblyLimits,
    /// Feedback limits.
    pub feedback: ReassemblyLimits,
}
/// Complete explicitly supplied FragmentFraming policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentFraming {
    /// Complete physical packet MTU.
    pub path_mtu: u64,
    /// Actual headers outside the fragment.
    pub outer_overhead_bytes: u64,
    /// Maximum complete logical message.
    pub max_message_bytes: u64,
    /// Maximum physical fragments per message.
    pub max_fragments: u16,
}
impl FragmentFraming {
    fn build(self) -> io::Result<codec::FragmentConfig> {
        Ok(codec::FragmentConfig {
            path_mtu: usize::try_from(self.path_mtu).map_err(invalid)?,
            outer_overhead_bytes: usize::try_from(self.outer_overhead_bytes).map_err(invalid)?,
            max_message_bytes: usize::try_from(self.max_message_bytes).map_err(invalid)?,
            max_fragments: self.max_fragments,
        })
    }
    fn from_policy(value: codec::FragmentConfig) -> io::Result<Self> {
        Ok(Self {
            path_mtu: u64::try_from(value.path_mtu).map_err(invalid)?,
            outer_overhead_bytes: u64::try_from(value.outer_overhead_bytes).map_err(invalid)?,
            max_message_bytes: u64::try_from(value.max_message_bytes).map_err(invalid)?,
            max_fragments: value.max_fragments,
        })
    }
}
/// Complete explicitly supplied ReassemblyLimits policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReassemblyLimits {
    /// Maximum complete logical body.
    pub max_message_bytes: u64,
    /// Maximum incomplete messages.
    pub max_messages: u64,
    /// Maximum declared fragment payload.
    pub max_fragment_payload_bytes: u16,
    /// Maximum fragments per message.
    pub max_fragments_per_message: u16,
    /// Maximum total retained fragment slots.
    pub max_total_fragments: u64,
    /// Maximum incomplete payload reservation.
    pub max_reserved_bytes: u64,
    /// Original first-arrival lifetime in runtime microseconds.
    pub max_lifetime_ticks: u64,
    /// Message-ID tombstone window.
    pub replay_window: u64,
}
impl ReassemblyLimits {
    fn build(self) -> io::Result<codec::ReassemblyConfig> {
        Ok(codec::ReassemblyConfig {
            max_message_bytes: usize::try_from(self.max_message_bytes).map_err(invalid)?,
            max_messages: usize::try_from(self.max_messages).map_err(invalid)?,
            max_fragment_payload_bytes: self.max_fragment_payload_bytes,
            max_fragments_per_message: self.max_fragments_per_message,
            max_total_fragments: usize::try_from(self.max_total_fragments).map_err(invalid)?,
            max_reserved_bytes: usize::try_from(self.max_reserved_bytes).map_err(invalid)?,
            max_lifetime_ticks: self.max_lifetime_ticks,
            replay_window: usize::try_from(self.replay_window).map_err(invalid)?,
        })
    }
    fn from_policy(value: codec::ReassemblyConfig) -> io::Result<Self> {
        Ok(Self {
            max_message_bytes: u64::try_from(value.max_message_bytes).map_err(invalid)?,
            max_messages: u64::try_from(value.max_messages).map_err(invalid)?,
            max_fragment_payload_bytes: value.max_fragment_payload_bytes,
            max_fragments_per_message: value.max_fragments_per_message,
            max_total_fragments: u64::try_from(value.max_total_fragments).map_err(invalid)?,
            max_reserved_bytes: u64::try_from(value.max_reserved_bytes).map_err(invalid)?,
            max_lifetime_ticks: value.max_lifetime_ticks,
            replay_window: u64::try_from(value.replay_window).map_err(invalid)?,
        })
    }
}
impl FragmentDirection {
    fn build(self) -> io::Result<engine::FragmentDirection> {
        Ok(engine::FragmentDirection {
            framing: self.framing.build()?,
            reassembly: engine::ReassemblyPolicies {
                systematic: self.reassembly.systematic.build()?,
                repair: self.reassembly.repair.build()?,
                feedback: self.reassembly.feedback.build()?,
            },
            labels: self.labels.map(codec::SessionId),
            first_message: codec::MessageId(self.first_message),
        })
    }
    fn from_policy(value: engine::FragmentDirection) -> io::Result<Self> {
        Ok(Self {
            framing: FragmentFraming::from_policy(value.framing)?,
            reassembly: FragmentReassembly {
                systematic: ReassemblyLimits::from_policy(value.reassembly.systematic)?,
                repair: ReassemblyLimits::from_policy(value.reassembly.repair)?,
                feedback: ReassemblyLimits::from_policy(value.reassembly.feedback)?,
            },
            labels: value.labels.map(|v| v.0),
            first_message: value.first_message.0,
        })
    }
}
impl RollingFragments {
    pub(crate) fn build(self) -> io::Result<engine::FragmentPolicy> {
        if self.version != 1 {
            return Err(invalid("unsupported selected fragment policy version"));
        }
        Ok(engine::FragmentPolicy {
            forward: self.forward.build()?,
            reverse: self.reverse.build()?,
        })
    }
    pub(crate) fn from_policy(value: engine::FragmentPolicy) -> io::Result<Self> {
        Ok(Self {
            version: 1,
            forward: FragmentDirection::from_policy(value.forward)?,
            reverse: FragmentDirection::from_policy(value.reverse)?,
        })
    }
}
/// Immutable request and actual selected generation are separate observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentStatus {
    /// Complete authenticated request.
    pub requested: RollingFragments,
    /// Current Engine policy, absent before a report or in another family.
    pub effective: Option<RollingFragments>,
    /// Actual current Engine reassembly and completed-body custody, when selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<FragmentIngress>,
    /// Actual current Engine logical reservations and whole physical completions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statistics: Option<FragmentCounters>,
    /// Actual cumulative Common runtime data-fragment pressure drops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_drops: Option<u64>,
    /// Actual cumulative Common runtime dedicated-feedback-slot pressure drops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback_drops: Option<u64>,
    /// Fragment policies cannot change within this establishment.
    pub policy_switching: bool,
}

/// Actual active-generation custody in systematic, repair and feedback order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentIngress {
    /// Actual incomplete message counts in the three independent reassemblers.
    pub pending: [u64; 3],
    /// Original arrivals of complete bodies held on actual decoder backpressure.
    pub held_received_micros: [Option<u64>; 3],
    /// Original effective caps of those complete bodies; retries never renew them.
    pub held_caps_micros: [Option<u64>; 3],
    /// Actual final-fragment protection numbers, without authority or delivery claims.
    pub held_numbers: [Option<u64>; 3],
}
impl FragmentIngress {
    fn observe(value: engine::FragmentIngressSnapshot) -> io::Result<Self> {
        Ok(Self {
            pending: [
                u64::try_from(value.pending[0]).map_err(invalid)?,
                u64::try_from(value.pending[1]).map_err(invalid)?,
                u64::try_from(value.pending[2]).map_err(invalid)?,
            ],
            held_received_micros: value.held_received.map(|v| v.map(|at| at.0)),
            held_caps_micros: value.held_caps.map(|v| v.map(|at| at.0)),
            held_numbers: value.held_numbers,
        })
    }
}
/// Actual current-generation counters; reservations are separate from whole writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentCounters {
    /// Logical groups reserved once from the shared budget.
    pub groups_reserved: u64,
    /// Physical fragments whose whole write was observed, including late facts.
    pub packets_written: u64,
    /// Exact full-wire bytes of those observed physical writes.
    pub wire_bytes_written: u64,
    /// Logical groups with every physical fragment actually written.
    pub groups_written: u64,
}
impl From<engine::FragmentStatistics> for FragmentCounters {
    fn from(value: engine::FragmentStatistics) -> Self {
        Self {
            groups_reserved: value.groups_reserved,
            packets_written: value.packets_written,
            wire_bytes_written: value.wire_bytes_written,
            groups_written: value.groups_written,
        }
    }
}
impl FragmentStatus {
    pub(crate) fn observe(
        requested: engine::FragmentPolicy,
        snapshot: Option<&l2tunnel_runtime::secure_udp::transport::CommonSnapshot>,
    ) -> io::Result<Self> {
        Ok(Self {
            requested: RollingFragments::from_policy(requested)?,
            effective: snapshot
                .and_then(|v| v.rolling_fragments)
                .map(RollingFragments::from_policy)
                .transpose()?,
            ingress: snapshot
                .and_then(|v| v.fragment_ingress)
                .map(FragmentIngress::observe)
                .transpose()?,
            statistics: snapshot
                .and_then(|v| v.fragment_statistics)
                .map(FragmentCounters::from),
            data_drops: snapshot.map(|v| v.fragment_data_drops),
            feedback_drops: snapshot.map(|v| v.fragment_feedback_drops),
            policy_switching: false,
        })
    }
}

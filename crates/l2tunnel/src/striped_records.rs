//! Packed native units over a single scoped, physical mixed-packet recovery owner.
mod endpoint;
pub mod native;
use crate::{
    aligned::NativePolicy,
    codec::{aligned_receiver as receiver, aligned_storage, packed_sender},
    fec::{
        self, FecContext, GenerationId,
        mixed_datagram::Profile,
        striped_group::{self, ReceiveWindow, schedule::RecoveryTiming},
    },
    record_configuration::Error,
};
pub(crate) use endpoint::Endpoint;

/// One endpoint's independent mixed-source custody in the current epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStatus {
    /// Global direction emitted by this endpoint.
    pub send_direction: fec::Direction,
    /// Coding stream of its local producer.
    pub send_stream: u32,
    /// Assigned producer sources awaiting peer confirmation, including staged inputs.
    pub send_outstanding: usize,
    /// Physically retained source slots, including acknowledged parts of one group.
    pub send_retained: usize,
    /// Local batch timing (microseconds) and sizes at the point of sealing.
    pub send_formation: fec::striped_group::GroupFormation,
    /// Physically accepted local data bytes and packets, by scheduling reason.
    pub send_paid: fec::striped_group::schedule::SendStats,
    /// Local feedback traffic about the opposite direction, after carrier acceptance.
    pub feedback_paid: fec::striped_group::schedule::Paid,
    /// Highest inclusive authenticated peer receipt applied by this producer.
    pub send_confirmed: Option<GenerationId>,
    /// Coding stream of its local consumer (opposite data direction).
    pub receive_stream: u32,
    /// Highest contiguous native-committed source.
    pub receive_confirmed: Option<GenerationId>,
    /// First source outside that prefix; absent after committing the maximum ID.
    pub receive_frontier: Option<GenerationId>,
    /// Highest logical source known from an authentic sealed group.
    pub receive_sealed: Option<GenerationId>,
    /// Uncommitted originals in groups the consumer has admitted.
    pub receive_uncommitted_in_groups: usize,
    /// All uncommitted original IDs through the sealed horizon, including unseen gaps.
    pub receive_uncommitted_through_sealed: usize,
}
pub(crate) use endpoint::StoragePlan;

fn scratch(len: usize) -> Result<Vec<u8>, native::NativeError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| native::NativeError::Capacity)?;
    if bytes.capacity() != len {
        return Err(native::NativeError::Capacity);
    }
    bytes.resize(len, 0);
    Ok(bytes)
}

/// Complete configuration for one global direction. Clocks are injected microseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Direction {
    /// Exact native record/header selection.
    pub native_policy: NativePolicy,
    /// Compact encoder, packing bounds and absolute unit numbering.
    pub packing: packed_sender::Config,
    /// Native decoder, fragment and retained-history limits.
    pub receiver: receiver::Limits,
    /// Physical data/parity cells and plaintext MTU.
    pub profile: Profile,
    /// Initial logical recovery source, independent of packed unit and record IDs.
    pub first: GenerationId,
    /// Maximum simultaneously outstanding logical recovery sources.
    pub source_limit: usize,
    /// Maximum expanded bytes held across receiver groups.
    pub expanded_limit: usize,
    /// Maximum time after admission of the oldest source before sealing its group.
    pub hold_micros: u64,
    /// Feedback, repeat and quiet-tail intervals.
    pub timing: RecoveryTiming,
    /// Charged underlay, carrier and record-protection bytes per data member.
    pub overhead_bytes: usize,
    /// Authenticated coding stream within this epoch and direction.
    pub stream: u32,
    /// Maximum age of input still in the native record encoder.
    pub codec_stage_micros: u64,
    /// Maximum time allowed for a pending native delivery.
    pub native_stall_micros: u64,
}

impl Direction {
    /// Preflight the actual Packed encoder selected for this data direction.
    pub fn packing_plan(self) -> Result<aligned_storage::PackedSenderPlan, aligned_storage::Error> {
        if self.native_policy.uses_ip_headers() {
            aligned_storage::PackedSenderPlan::for_ip_config(self.packing)
        } else {
            aligned_storage::PackedSenderPlan::for_config(self.packing)
        }
    }

    /// Preflight the decoder including its selected independent-delivery history.
    pub fn receiver_plan(self) -> Result<aligned_storage::ReceiverPlan, aligned_storage::Error> {
        if self.native_policy.is_ip() && self.native_policy != NativePolicy::FixedAnchorIpHeaders {
            aligned_storage::ReceiverPlan::for_ip_limits_with_early_replay(self.receiver)
        } else {
            self.native_policy.receiver_plan(self.receiver)
        }
    }

    /// Check codec, shortened-group progress, retained memory and native geometry together.
    pub fn validate(self) -> Result<(), Error> {
        let r = self.receiver;
        let p = self.packing;
        if !(1..=65_535).contains(&self.profile.max_body_bytes)
            || !(1..=65_535).contains(&self.profile.max_wire_bytes)
            || !(1..=65_536).contains(&self.source_limit)
        {
            return Err(Error::Profile);
        }
        p.memory_bound_bytes().map_err(|_| Error::Profile)?;
        r.batch_memory_bound_bytes().map_err(|_| Error::Profile)?;
        self.packing_plan().map_err(|_| Error::Profile)?;
        self.receiver_plan().map_err(|_| Error::Profile)?;
        self.timing.validate().map_err(|_| Error::Profile)?;
        let max_original =
            striped_group::original_limit(self.profile).map_err(|_| Error::Profile)?;
        let reserve = ReceiveWindow::frontier_reserve(self.profile, self.source_limit)
            .map_err(|_| Error::Profile)?;
        let fragments = (r.body.max_frame_bytes + 29)
            .clamp(69, 65_535)
            .div_ceil(r.body.symbol_bytes - 8);
        let group = usize::from(self.profile.data_cells) + usize::from(self.profile.parity_cells);
        // The final source in the oldest group can start a record whose tail
        // still needs several new source slots. Credit returns at native commit.
        let head_slots = group.min(self.source_limit) + fragments - 1;
        // Later shortened groups can each hold two mixed rows and one original.
        // Keep room for continuations even when the frontier row is only partly
        // committed and the rest of the source aperture was received first.
        let receive_bytes = self
            .profile
            .max_body_bytes
            .checked_mul(3)
            .and_then(|n| n.checked_mul(self.source_limit))
            .and_then(|n| n.checked_add(reserve))
            .ok_or(Error::Integer)?;
        // Compact sources use at most one 10-byte absolute unit number,
        // two flags/count bytes and eight bytes per absolute record number.
        let max_packed = p.packing.symbol_bytes + 12 + 8 * usize::from(p.max_units);
        if !self.native_policy.available()
            || self.codec_stage_micros == 0
            || self.native_stall_micros == 0
            || self.hold_micros == 0
            || self.source_limit < head_slots
            || self.expanded_limit < receive_bytes
            || max_packed > max_original
            || p.sender.body != r.body
            || p.sender.channels != r.channels
            || p.sender.first_record != r.first_record
            || p.first_unit != r.first_source
            || r.source_window < usize::from(p.max_units)
            || r.max_fragments_per_record < fragments
            || (self.native_policy.is_stateless()
                && (r.body.predictive
                    || r.body.elide_payload_length
                    || r.body.timestamp_pair_dictionary))
        {
            return Err(Error::Profile);
        }
        Ok(())
    }

    /// Validate the complete physical IP budget before peer negotiation.
    pub fn validate_path(self, mtu: usize) -> Result<(), Error> {
        self.validate()?;
        if self
            .profile
            .max_wire_bytes
            .checked_add(self.overhead_bytes)
            .is_none_or(|n| n > mtu)
        {
            return Err(Error::PathMtu);
        }
        Ok(())
    }

    /// Construct the coding domain from an established native record scope.
    pub fn context(self, scope: receiver::Scope) -> FecContext {
        FecContext {
            session: fec::SessionId(scope.session),
            epoch: fec::Epoch(scope.epoch.0),
            channel: fec::ChannelId(self.stream),
            direction: match scope.direction {
                receiver::Direction::InitiatorToResponder => fec::Direction::ClientToServer,
                receiver::Direction::ResponderToInitiator => fec::Direction::ServerToClient,
            },
        }
    }
}

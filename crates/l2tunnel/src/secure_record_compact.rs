//! Selected final Common framing without continued appearance envelopes.
//!
//! Full scope and configuration remain local authenticated context. The wire
//! carries a kind/reader selector, low packet number, selected body and check.
//! Data CRC is explicitly not authentication. Reliable-retiring feedback uses
//! its own strongly authenticated domain on the same carrier.

use super::{Capacity, Class, Error, Opened, Records, Scope, Sealed};
use crate::{cover, security};
use l2tunnel_recovery::{CompactPacketKind, CompactPacketView, RecoveryError};
use security::compact as sec;
use std::fmt;

/// One kind/registered-reader byte and a four-byte low packet number.
pub const PREFIX_BYTES: usize = 5;
/// Complete outer overhead of either selected short-check data profile.
pub const DATA_OVERHEAD: usize = PREFIX_BYTES + 4;
/// Complete outer overhead of management and retiring feedback.
pub const AUTHENTICATED_OVERHEAD: usize = PREFIX_BYTES + 16;

/// Final typed algorithm serialization or selected record protection refusal.
#[derive(Debug)]
pub enum AlgorithmError {
    /// The actual borrowed algorithm view is not canonically representable.
    Algorithm(RecoveryError),
    /// Scope, capacity, selected protection or counter refusal.
    Record(Error),
}
impl fmt::Display for AlgorithmError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "compact algorithm record: {self:?}")
    }
}
impl std::error::Error for AlgorithmError {}
impl From<RecoveryError> for AlgorithmError {
    fn from(value: RecoveryError) -> Self {
        Self::Algorithm(value)
    }
}
impl From<Error> for AlgorithmError {
    fn from(value: Error) -> Self {
        Self::Record(value)
    }
}

/// Explicit authenticated compact selection; there is no implicit default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    /// Selected four-byte data check, with different integrity guarantees.
    pub protection: sec::Protection,
    /// Bounded sequence reconstruction and lifetime failed-check allowance.
    pub limits: sec::Selection,
}

/// Actual lifetime failed-check observations, independent of packet replay drops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckStatus {
    /// Failed checks in the data owner; success does not reset this count.
    pub data: u32,
    /// Failed authentication attempts in the reliable-retiring feedback owner.
    pub feedback: u32,
    /// Failed authentication attempts in the management owner.
    pub control: u32,
    /// Explicit per-owner limit bound by the establishment contract.
    pub limit: u32,
}
impl Selection {
    /// Validate supported data profiles and explicit nonzero finite limits.
    pub fn validate(self) -> Result<(), Error> {
        if !matches!(
            self.protection,
            sec::Protection::Aes128Ccm4 | sec::Protection::ChaCha20Crc32c
        ) || self.limits.max_forward_packets == 0
            || self.limits.max_forward_packets > i32::MAX as u32
            || self.limits.max_failed_checks == 0
        {
            return Err(security::Error::InvalidLimits.into());
        }
        Ok(())
    }
}

/// Transcript-selected namespace for the established final records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Layout {
    /// Original UDP v3, preserving its existing byte format.
    Original,
    /// Initial carrier tails and final records occupy disjoint namespaces.
    Carrier,
}
impl Layout {
    /// Parse a final route without attempting a legacy protocol fallback.
    pub fn kind(self, byte: u8) -> Result<Kind, Error> {
        match (self, byte) {
            (Self::Original, 0..=63) | (Self::Carrier, 128..=191) => Ok(Kind::Data),
            (Self::Original, 64..=127) | (Self::Carrier, 192..=255) => Ok(Kind::Feedback),
            (Self::Original, 128) | (Self::Carrier, 0) => Ok(Kind::Control),
            (Self::Carrier, 1) => Ok(Kind::CarrierControl),
            _ => Err(Error::Malformed),
        }
    }
    fn route(self, kind: Kind, slot: u8) -> Result<u8, Error> {
        if slot > 63 {
            return Err(Error::Scope);
        }
        match (self, kind) {
            (Self::Original, Kind::Data) => Ok(slot),
            (Self::Original, Kind::Feedback) => Ok(0x40 | slot),
            (Self::Original, Kind::Control) => Ok(0x80),
            (Self::Carrier, Kind::Data) => Ok(0x80 | slot),
            (Self::Carrier, Kind::Feedback) => Ok(0xc0 | slot),
            (Self::Carrier, Kind::Control) => Ok(0),
            (Self::Carrier, Kind::CarrierControl) => Ok(1),
            _ => Err(Error::ScopeState),
        }
    }
}

/// Final packet authority, separate from the selected algorithm's header union.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Source/repair data; CRC selection grants no authenticated control rights.
    Data,
    /// Reliable-retiring feedback under the dedicated strong domain.
    Feedback,
    /// Fixed-scope management under the independent strong domain.
    Control,
    /// Carrier window and liveness controls sharing the management counter.
    CarrierControl,
}
impl Kind {
    fn class(self) -> Class {
        match self {
            Self::Data | Self::Feedback => Class::User,
            Self::Control | Self::CarrierControl => Class::Control,
        }
    }
    fn tag_bytes(self) -> usize {
        match self {
            Self::Data => 4,
            Self::Feedback | Self::Control | Self::CarrierControl => 16,
        }
    }
}

pub(super) struct Owners {
    pub(super) selection: Selection,
    layout: Layout,
    pub(super) data_sender: sec::Sender,
    data_receiver: sec::Receiver,
    pub(super) control_sender: sec::Sender,
    control_receiver: sec::Receiver,
    feedback_sender: sec::Sender,
    feedback_receiver: sec::Receiver,
    pub(super) data_slot: u8,
    pub(super) additional_slot: Option<u8>,
}

pub(super) fn capacity(
    cover: cover::Config,
    limits: security::Limits,
    tag: usize,
    plaintext_bytes: usize,
) -> Result<Capacity, Error> {
    if plaintext_bytes > limits.max_body_bytes {
        return Err(Error::TooLarge);
    }
    let packet_bytes = plaintext_bytes
        .checked_add(PREFIX_BYTES)
        .and_then(|bytes| bytes.checked_add(tag))
        .ok_or(Error::TooLarge)?;
    if packet_bytes > cover.limits().max_packet_bytes {
        return Err(Error::TooLarge);
    }
    Ok(Capacity {
        plaintext_bytes,
        seal_workspace_bytes: packet_bytes,
        open_workspace_bytes: plaintext_bytes.checked_add(tag).ok_or(Error::TooLarge)?,
        packet_bytes,
    })
}

impl Records {
    /// Install the explicitly selected compact format from the authenticated root.
    ///
    /// The establishment owner must bind the complete selection into its transcript.
    /// The cover remains the initial appearance; established packets are unwrapped.
    /// No fallback, additional handshake, clock or packet loop is created here.
    #[allow(clippy::too_many_arguments)]
    pub fn new_compact(
        root: security::SessionRoot,
        lane: security::LaneId,
        limits: security::Limits,
        cover: cover::Config,
        control: Scope,
        data: Scope,
        selection: Selection,
    ) -> Result<Self, Error> {
        Self::new_compact_with_layout(
            root,
            lane,
            limits,
            cover,
            control,
            data,
            selection,
            Layout::Original,
        )
    }

    /// Install the namespace explicitly bound by the authenticated carrier contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new_compact_with_layout(
        mut root: security::SessionRoot,
        lane: security::LaneId,
        limits: security::Limits,
        cover: cover::Config,
        control: Scope,
        data: Scope,
        selection: Selection,
        layout: Layout,
    ) -> Result<Self, Error> {
        selection.validate()?;
        capacity(cover, limits, 16, limits.max_body_bytes)?;
        let mut owners = Vec::new();
        owners.try_reserve_exact(1).map_err(|_| Error::Allocation)?;
        owners.push(Owners {
            selection,
            layout,
            data_sender: root.compact_sender(
                security::Purpose::Data,
                lane,
                limits,
                selection.protection,
                selection.limits,
            )?,
            data_receiver: root.compact_receiver(
                security::Purpose::Data,
                lane,
                limits,
                selection.protection,
                selection.limits,
            )?,
            control_sender: root.compact_sender(
                security::Purpose::Management,
                lane,
                limits,
                sec::Protection::ChaCha20Poly1305,
                selection.limits,
            )?,
            control_receiver: root.compact_receiver(
                security::Purpose::Management,
                lane,
                limits,
                sec::Protection::ChaCha20Poly1305,
                selection.limits,
            )?,
            feedback_sender: root.compact_sender(
                security::Purpose::Recovery,
                lane,
                limits,
                sec::Protection::ChaCha20Poly1305,
                selection.limits,
            )?,
            feedback_receiver: root.compact_receiver(
                security::Purpose::Recovery,
                lane,
                limits,
                sec::Protection::ChaCha20Poly1305,
                selection.limits,
            )?,
            data_slot: 0,
            additional_slot: None,
        });
        Ok(Self {
            cover,
            limits,
            protection: security::Protection::ChaCha20Poly1305,
            control,
            data,
            additional: None,
            owners: super::Owners::Compact(owners),
        })
    }

    /// Actual installed format observation, independent of requested configuration.
    pub fn is_compact(&self) -> bool {
        matches!(self.owners, super::Owners::Compact(_))
    }
    /// Actual installed data check and bounded failure/reconstruction policy.
    pub fn compact_selection(&self) -> Option<Selection> {
        match &self.owners {
            super::Owners::Compact(owners) => Some(owners[0].selection),
            _ => None,
        }
    }
    /// Actual installed final namespace.
    pub fn compact_layout(&self) -> Option<Layout> {
        match &self.owners {
            super::Owners::Compact(owners) => Some(owners[0].layout),
            _ => None,
        }
    }
    /// Actual compact singleton backing, excluding this Records inline layout.
    /// This is a Rust owner-layout charge, not allocator or crypto-provider RSS.
    pub fn compact_owner_bytes(&self) -> usize {
        match &self.owners {
            super::Owners::Compact(owners) => owners.capacity() * std::mem::size_of::<Owners>(),
            _ => 0,
        }
    }
    /// Actual independent check budgets; no scope operation resets them.
    pub fn compact_check_status(&self) -> Option<CheckStatus> {
        match &self.owners {
            super::Owners::Compact(owners) => {
                let owner = &owners[0];
                Some(CheckStatus {
                    data: owner.data_receiver.failed_checks(),
                    feedback: owner.feedback_receiver.failed_checks(),
                    control: owner.control_receiver.failed_checks(),
                    limit: owner.selection.limits.max_failed_checks,
                })
            }
            _ => None,
        }
    }
    /// Exact kind-specific full packet size, including its actual check.
    /// Legacy formats keep their unchanged class-independent packet size.
    pub fn capacity_for(&self, kind: Kind, bytes: usize) -> Result<Capacity, Error> {
        if !self.is_compact() {
            return self.capacity(bytes);
        }
        capacity(self.cover, self.limits, kind.tag_bytes(), bytes)
    }
    /// Next independent strongly authenticated feedback number, without reservation.
    pub fn next_feedback_number(&self) -> Result<security::PacketNumber, Error> {
        match &self.owners {
            super::Owners::Compact(owners) => Ok(owners[0].feedback_sender.next_number()),
            _ => Err(Error::ScopeState),
        }
    }
    /// Seal reliable-retiring feedback using its registered epoch and strong owner.
    /// Algorithm feedback remains lossy; no reliable control-stream bypass is added.
    pub fn seal_feedback_in(
        &mut self,
        scope: Scope,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.seal_compact(Kind::Feedback, scope, outer, plaintext, workspace, output)
    }

    /// Encode the actual selected CompactARQ union directly into final protection.
    /// No legacy recovery context or Reliable wrapper is serialized in this path.
    /// Call from the recovery owner's transactional encoder callback, then retain
    /// its physical-output witness until the complete final packet is accepted.
    pub fn seal_compact_arq_in(
        &mut self,
        scope: Scope,
        outer: cover::PacketMeta,
        view: CompactPacketView<'_>,
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, AlgorithmError> {
        if !self.is_compact() {
            return Err(Error::ScopeState.into());
        }
        let kind = match view.kind() {
            CompactPacketKind::Data => Kind::Data,
            CompactPacketKind::Feedback => Kind::Feedback,
        };
        let length = view.compact_encoded_len()?;
        let capacity = self.capacity_for(kind, length)?;
        if outer.phase != cover::Phase::Established {
            return Err(Error::Phase.into());
        }
        if self.registered_scope(Class::User, scope.epoch)? != scope {
            return Err(Error::Scope.into());
        }
        if workspace.len() < capacity.seal_workspace_bytes || output.len() < capacity.packet_bytes {
            return Err(Error::OutputTooSmall.into());
        }
        view.encode_compact_into(workspace)?;
        Ok(self.seal_compact_from(
            kind,
            scope,
            outer,
            &workspace[..length],
            workspace.len(),
            &[],
            output,
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_compact(
        &mut self,
        kind: Kind,
        scope: Scope,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        self.seal_compact_from(kind, scope, outer, plaintext, workspace.len(), &[], output)
    }

    /// Protect the selected final record and canonical carrier metadata once.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_compact_with_carrier(
        &mut self,
        kind: Kind,
        scope: Scope,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        carrier_aad: &[u8],
        workspace: &mut [u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        if self.compact_layout() != Some(Layout::Carrier) {
            return Err(Error::ScopeState);
        }
        self.seal_compact_from(
            kind,
            scope,
            outer,
            plaintext,
            workspace.len(),
            carrier_aad,
            output,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_compact_from(
        &mut self,
        kind: Kind,
        scope: Scope,
        outer: cover::PacketMeta,
        plaintext: &[u8],
        workspace_bytes: usize,
        carrier_aad: &[u8],
        output: &mut [u8],
    ) -> Result<Sealed, Error> {
        if outer.phase != cover::Phase::Established {
            return Err(Error::Phase);
        }
        if self.registered_scope(kind.class(), scope.epoch)? != scope {
            return Err(Error::Scope);
        }
        let cap = self.capacity_for(kind, plaintext.len())?;
        if workspace_bytes < cap.seal_workspace_bytes || output.len() < cap.packet_bytes {
            return Err(Error::OutputTooSmall);
        }
        let super::Owners::Compact(owners) = &mut self.owners else {
            return Err(Error::ScopeState);
        };
        let owner = &mut owners[0];
        let slot = if kind.class() == Class::Control {
            0
        } else if scope == self.data {
            owner.data_slot
        } else {
            owner.additional_slot.ok_or(Error::ScopeState)?
        };
        let route = owner.layout.route(kind, slot)?;
        let mut aad = [0; security::MAX_METADATA_BYTES];
        let aad_len = carrier_aad
            .len()
            .checked_add(1)
            .filter(|len| *len <= aad.len())
            .ok_or(Error::TooLarge)?;
        aad[0] = route;
        aad[1..aad_len].copy_from_slice(carrier_aad);
        let metadata = security::Metadata {
            epoch: scope.epoch,
            configuration: scope.configuration,
            extra: &aad[..aad_len],
        };
        let sender = match kind {
            Kind::Data => &mut owner.data_sender,
            Kind::Feedback => &mut owner.feedback_sender,
            Kind::Control | Kind::CarrierControl => &mut owner.control_sender,
        };
        let sealed = sender.seal(metadata, plaintext, &mut output[1..cap.packet_bytes])?;
        output[0] = route;
        Ok(Sealed {
            number: sealed.number,
            generation: sealed.generation,
            bytes: sealed.bytes.checked_add(1).ok_or(Error::TooLarge)?,
        })
    }

    pub(super) fn open_compact(
        &mut self,
        packet: &[u8],
        workspace: &mut [u8],
        plaintext: &mut [u8],
    ) -> Result<Opened, Error> {
        self.open_compact_from(packet, &[], workspace, plaintext)
    }

    /// Verify canonical carrier metadata before committing the record replay state.
    pub fn open_compact_with_carrier(
        &mut self,
        packet: &[u8],
        carrier_aad: &[u8],
        workspace: &mut [u8],
        plaintext: &mut [u8],
    ) -> Result<Opened, Error> {
        if self.compact_layout() != Some(Layout::Carrier) {
            return Err(Error::ScopeState);
        }
        self.open_compact_from(packet, carrier_aad, workspace, plaintext)
    }

    fn open_compact_from(
        &mut self,
        packet: &[u8],
        carrier_aad: &[u8],
        workspace: &mut [u8],
        plaintext: &mut [u8],
    ) -> Result<Opened, Error> {
        let byte = *packet.first().ok_or(Error::Malformed)?;
        let kind = self.compact_layout().ok_or(Error::ScopeState)?.kind(byte)?;
        let mut aad = [0; security::MAX_METADATA_BYTES];
        let aad_len = carrier_aad
            .len()
            .checked_add(1)
            .filter(|len| *len <= aad.len())
            .ok_or(Error::TooLarge)?;
        aad[0] = byte;
        aad[1..aad_len].copy_from_slice(carrier_aad);
        let body_bytes = packet
            .len()
            .checked_sub(PREFIX_BYTES + kind.tag_bytes())
            .ok_or(Error::Malformed)?;
        let cap = self.capacity_for(kind, body_bytes)?;
        if workspace.len() < cap.open_workspace_bytes || plaintext.len() < body_bytes {
            return Err(Error::OutputTooSmall);
        }
        let super::Owners::Compact(owners) = &mut self.owners else {
            return Err(Error::ScopeState);
        };
        let owner = &mut owners[0];
        let slot = byte & 0x3f;
        let scope = if kind.class() == Class::Control {
            self.control
        } else if slot == owner.data_slot {
            self.data
        } else if Some(slot) == owner.additional_slot {
            self.additional.ok_or(Error::Scope)?.scope
        } else {
            return Err(Error::Scope);
        };
        let receiver = match kind {
            Kind::Data => &mut owner.data_receiver,
            Kind::Feedback => &mut owner.feedback_receiver,
            Kind::Control | Kind::CarrierControl => &mut owner.control_receiver,
        };
        let opened = receiver.open(
            security::Metadata {
                epoch: scope.epoch,
                configuration: scope.configuration,
                extra: &aad[..aad_len],
            },
            &packet[1..],
            workspace,
        )?;
        plaintext[..opened.bytes].copy_from_slice(&workspace[..opened.bytes]);
        Ok(Opened {
            class: kind.class(),
            scope,
            number: opened.number,
            generation: opened.generation,
            bytes: opened.bytes,
            feedback: kind == Kind::Feedback,
            authenticated: kind != Kind::Data
                || owner.selection.protection != sec::Protection::ChaCha20Crc32c,
        })
    }
}

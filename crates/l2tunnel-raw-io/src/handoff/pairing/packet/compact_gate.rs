//! Bounded untrusted final candidates sharing the original lane queue.
use super::super::compact::{FinalKind, FinalMetadata};
use super::*;

impl GateState {
    pub(in crate::handoff::pairing::packet) fn ingest_final(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let context = self.final_context.ok_or(Error::Proof)?;
        let packet = match packet::inspect(self.config, bytes) {
            Ok(packet) if packet.phase_shape() => packet,
            _ => return self.reject(),
        };
        let Some(kind) = FinalKind::inspect(packet.payload) else {
            return self.reject();
        };
        if packet.payload.len() < 5 || bytes.len() > usize::from(self.policy.mtu) {
            return self.reject();
        }
        let control = kind == FinalKind::CarrierControl;
        let controls = self
            .incoming
            .iter()
            .filter(|cell| {
                cell.final_metadata
                    .map_or(cell.header.kind.control(), |meta| {
                        meta.kind == FinalKind::CarrierControl
                    })
            })
            .count();
        let finals = self
            .incoming
            .iter()
            .filter(|cell| {
                cell.final_metadata
                    .is_some_and(|meta| meta.kind != FinalKind::CarrierControl)
            })
            .count();
        if (control && controls >= 4)
            || (!control
                && self.records_outstanding + finals >= usize::from(self.policy.queue_packets))
        {
            return self.reject();
        }
        let metadata = FinalMetadata {
            context,
            lane: self.lane as u8,
            sender: if self.client { 2 } else { 1 },
            kind,
            sequence: packet.sequence,
            acknowledgment: packet.acknowledgment,
            window: packet.window,
            payload_bytes: u16::try_from(packet.payload.len()).map_err(|_| Error::Capacity)?,
        };
        if self.validate_final(metadata).is_err() {
            return self.reject();
        }
        let fence = self.fence.as_ref().ok_or(Error::Proof)?;
        let retired = u64::from(metadata.acknowledgment - fence.local);
        self.incoming.push_back(Cell {
            received_at: Instant::now(),
            final_metadata: Some(metadata),
            body: packet.payload.to_vec(),
            header: wire::Header {
                kind: if control {
                    wire::Kind::Window
                } else {
                    wire::Kind::Data
                },
                transaction: self.transaction,
                offset: u64::from(metadata.sequence - fence.peer),
                retired,
                right_edge: retired
                    .checked_add(fence.peer_horizon)
                    .ok_or(Error::Exhausted)?,
                body: metadata.payload_bytes,
            },
        });
        Ok(())
    }
    /// Read-only raw geometry/replay preflight before the sole verifier commits.
    pub(in crate::handoff::pairing::packet) fn validate_final(
        &self,
        metadata: FinalMetadata,
    ) -> Result<(), Error> {
        if self.final_context != Some(metadata.context)
            || usize::from(metadata.lane) != self.lane
            || metadata.sender != if self.client { 2 } else { 1 }
            || metadata.payload_bytes < 5
            || usize::from(metadata.payload_bytes) + 40 > usize::from(self.policy.mtu)
            || (metadata.kind == FinalKind::Data && self.half && (self.lane == 0) == self.client)
        {
            return Err(Error::Proof);
        }
        let f = self.fence.as_ref().ok_or(Error::Proof)?;
        let offset = u64::from(metadata.sequence.checked_sub(f.peer).ok_or(Error::Proof)?);
        let retired = u64::from(
            metadata
                .acknowledgment
                .checked_sub(f.local)
                .ok_or(Error::Proof)?,
        );
        let end = offset
            .checked_add(u64::from(metadata.payload_bytes))
            .ok_or(Error::Exhausted)?;
        let right = f
            .retired
            .checked_add(f.local_horizon)
            .ok_or(Error::Exhausted)?;
        let reserve = metadata.kind.reserve() * (u64::from(self.policy.mtu) - 40);
        if end >= u64::from(u32::MAX - f.peer)
            || end > right.saturating_sub(reserve)
            || end.saturating_add(f.local_horizon) < f.retired
            || retired > f.sent
            || metadata.window
                != u16::try_from(f.peer_horizon >> f.peer_scale).map_err(|_| Error::Proof)?
        {
            return Err(Error::Proof);
        }
        self.ranges
            .propose(offset, end, f.retired.max(end), f.local_horizon)?;
        Ok(())
    }
    pub(in crate::handoff::pairing::packet) fn commit_final(
        &mut self,
        metadata: FinalMetadata,
    ) -> Result<u64, Error> {
        self.validate_final(metadata)?;
        let f = self.fence.as_mut().ok_or(Error::Proof)?;
        let offset = u64::from(metadata.sequence - f.peer);
        let end = offset + u64::from(metadata.payload_bytes);
        self.ranges = self
            .ranges
            .propose(offset, end, f.retired.max(end), f.local_horizon)?;
        f.retired = f.retired.max(end);
        if metadata.kind != FinalKind::Data {
            f.peer_retired = f
                .peer_retired
                .max(u64::from(metadata.acknowledgment - f.local));
        }
        Ok(f.retired)
    }
    pub(in crate::handoff::pairing::packet) fn reject_final(&mut self) -> Result<(), Error> {
        self.reject()
    }
}

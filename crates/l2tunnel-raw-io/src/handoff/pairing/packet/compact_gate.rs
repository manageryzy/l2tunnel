//! Bounded untrusted final candidates sharing the original lane queue.
use super::super::compact::{FinalKind, FinalMetadata};
use super::*;

fn candidate_class(kind: FinalKind) -> u8 {
    match kind {
        FinalKind::CarrierControl => 0,
        FinalKind::Control => 1,
        FinalKind::Data | FinalKind::Feedback => 2,
    }
}

impl GateState {
    pub(in crate::handoff::pairing::packet) const fn tls_record_overhead(&self) -> usize {
        if self.tls_record_cover {
            super::super::compact::TLS_RECORD_HEADER_BYTES
        } else {
            0
        }
    }
    pub(in crate::handoff::pairing::packet) fn unwrap_final_payload<'a>(
        &self,
        payload: &'a [u8],
    ) -> Option<&'a [u8]> {
        if !self.tls_record_cover {
            return Some(payload);
        }
        if payload.len() < super::super::compact::TLS_RECORD_HEADER_BYTES + 5 {
            return None;
        }
        if payload[..3] != super::super::compact::TLS_APP_DATA_PREFIX {
            return None;
        }
        let declared = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
        let body = &payload[super::super::compact::TLS_RECORD_HEADER_BYTES..];
        (declared == body.len()).then_some(body)
    }
    pub(in crate::handoff::pairing::packet) fn final_candidate_diagnostics(
        &self,
        now: Instant,
    ) -> ([CandidateBufferSnapshot; 3], Option<FinalKind>, Option<u64>) {
        let upper = self.final_upper_capacity();
        let capacities = [
            4,
            if upper == 0 { 1 } else { upper },
            self.final_bulk_capacity(),
        ];
        let mut snapshots = [CandidateBufferSnapshot::default(); 3];
        for (index, snapshot) in snapshots.iter_mut().enumerate() {
            snapshot.capacity_packets = capacities[index];
            snapshot.capacity_payload_bytes =
                capacities[index] * (usize::from(self.policy.mtu) - 40);
            snapshot.counters = self.candidate_counters[index];
        }
        let mut selected_age = None;
        for cell in &self.incoming {
            if let Some(metadata) = cell.final_metadata {
                let snapshot = &mut snapshots[usize::from(candidate_class(metadata.kind))];
                snapshot.queued_packets += 1;
                snapshot.queued_payload_bytes += cell.body.len();
                let age = diagnostics::age_micros(now, cell.received_at);
                snapshot.oldest_age_micros =
                    Some(snapshot.oldest_age_micros.map_or(age, |old| old.max(age)));
                if self.final_selected == Some(metadata) {
                    selected_age = Some(age);
                }
            }
        }
        (
            snapshots,
            self.final_selected.map(|metadata| metadata.kind),
            selected_age,
        )
    }
    fn observe_final_admission(&mut self, kind: FinalKind, bytes: usize) {
        let class = usize::from(candidate_class(kind));
        let (packets, payload_bytes) = &mut self.candidate_queued[class];
        *packets = packets.saturating_add(1);
        *payload_bytes = payload_bytes.saturating_add(bytes);
        let counters = &mut self.candidate_counters[class];
        counters.admitted.record(bytes);
        counters.high_water_packets = counters.high_water_packets.max(*packets);
        counters.high_water_payload_bytes = counters.high_water_payload_bytes.max(*payload_bytes);
    }
    // These are untrusted candidate shares, not authenticated control authority.
    // At capacity one, upper control and bulk retain the original shared slot.
    pub(in crate::handoff::pairing::packet) fn final_upper_capacity(&self) -> usize {
        (usize::from(self.policy.queue_packets) / 2).min(4)
    }
    pub(in crate::handoff::pairing::packet) fn final_bulk_capacity(&self) -> usize {
        usize::from(self.policy.queue_packets) - self.final_upper_capacity()
    }
    pub(in crate::handoff::pairing::packet) fn select_final_candidate(
        &mut self,
    ) -> Result<Option<usize>, Error> {
        if let Some(selected) = self.final_selected {
            return self
                .incoming
                .iter()
                .position(|cell| cell.final_metadata == Some(selected))
                .map(Some)
                .ok_or(Error::Proof);
        }
        for distance in 0..3 {
            let class = (self.final_candidate_turn + distance) % 3;
            if let Some(index) = self.incoming.iter().position(|cell| {
                cell.final_metadata
                    .is_some_and(|metadata| candidate_class(metadata.kind) == class)
            }) {
                self.final_selected = self.incoming[index].final_metadata;
                return Ok(Some(index));
            }
        }
        Ok(None)
    }
    pub(in crate::handoff::pairing::packet) fn selected_final_candidate(
        &self,
        metadata: FinalMetadata,
    ) -> Result<usize, Error> {
        if self.final_selected != Some(metadata) {
            return Err(Error::Proof);
        }
        self.incoming
            .iter()
            .position(|cell| cell.final_metadata == Some(metadata))
            .ok_or(Error::Busy)
    }
    pub(in crate::handoff::pairing::packet) fn consume_final_candidate(
        &mut self,
        index: usize,
    ) -> Result<Cell, Error> {
        let metadata = self
            .incoming
            .get(index)
            .and_then(|cell| cell.final_metadata)
            .ok_or(Error::Proof)?;
        if self.final_selected != Some(metadata) {
            return Err(Error::Proof);
        }
        let cell = self.incoming.remove(index).ok_or(Error::Proof)?;
        let (packets, bytes) =
            &mut self.candidate_queued[usize::from(candidate_class(metadata.kind))];
        *packets = packets.saturating_sub(1);
        *bytes = bytes.saturating_sub(cell.body.len());
        self.final_selected = None;
        self.final_candidate_turn = (candidate_class(metadata.kind) + 1) % 3;
        Ok(cell)
    }
    pub(in crate::handoff::pairing::packet) fn ingest_final(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let context = self.final_context.ok_or(Error::Proof)?;
        let packet = match packet::inspect(self.config, bytes) {
            Ok(packet) if packet.phase_shape() => packet,
            _ => return self.reject(),
        };
        let Some(record_bytes) = self.unwrap_final_payload(packet.payload) else {
            return self.reject();
        };
        let Some(kind) = FinalKind::inspect(record_bytes) else {
            return self.reject();
        };
        if record_bytes.len() < 5 || bytes.len() > usize::from(self.policy.mtu) {
            self.candidate_counters[usize::from(candidate_class(kind))]
                .preflight_rejected
                .record(record_bytes.len());
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
        let upper = self
            .incoming
            .iter()
            .filter(|cell| {
                cell.final_metadata
                    .is_some_and(|meta| meta.kind == FinalKind::Control)
            })
            .count();
        let upper_capacity = self.final_upper_capacity();
        let class_full = if kind == FinalKind::Control {
            upper_capacity != 0 && upper >= upper_capacity
        } else {
            self.records_outstanding + finals - upper >= self.final_bulk_capacity()
        };
        if (control && controls >= 4)
            || (!control
                && (self.records_outstanding + finals >= usize::from(self.policy.queue_packets)
                    || class_full))
        {
            self.candidate_counters[usize::from(candidate_class(kind))]
                .capacity_refused
                .record(packet.payload.len());
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
            payload_bytes: u16::try_from(record_bytes.len()).map_err(|_| Error::Capacity)?,
        };
        if self.validate_final(metadata).is_err() {
            self.candidate_counters[usize::from(candidate_class(kind))]
                .preflight_rejected
                .record(record_bytes.len());
            return self.reject();
        }
        let fence = self.fence.as_ref().ok_or(Error::Proof)?;
        // validate_final above recovered both positions; recompute them identically.
        let retired = crate::handoff::pairing::packet::sequence::position(
            fence.local,
            metadata.acknowledgment,
            fence.sent,
        )
        .ok_or(Error::Proof)?;
        let offset = crate::handoff::pairing::packet::sequence::position(
            fence.peer,
            metadata.sequence,
            fence.retired,
        )
        .ok_or(Error::Proof)?;
        self.incoming.push_back(Cell {
            received_at: Instant::now(),
            final_metadata: Some(metadata),
            body: record_bytes.to_vec(),
            header: wire::Header {
                kind: if control {
                    wire::Kind::Window
                } else {
                    wire::Kind::Data
                },
                transaction: self.transaction,
                offset,
                retired,
                right_edge: retired
                    .checked_add(fence.peer_horizon)
                    .ok_or(Error::Exhausted)?,
                body: metadata.payload_bytes,
            },
        });
        self.observe_final_admission(kind, record_bytes.len());
        Ok(())
    }
    /// Read-only raw geometry/replay preflight before the sole verifier commits.
    pub(in crate::handoff::pairing::packet) fn validate_final(
        &self,
        metadata: FinalMetadata,
    ) -> Result<(), Error> {
        let wire_bytes = usize::from(metadata.payload_bytes)
            .checked_add(self.tls_record_overhead())
            .ok_or(Error::Exhausted)?;
        if self.final_context != Some(metadata.context)
            || usize::from(metadata.lane) != self.lane
            || metadata.sender != if self.client { 2 } else { 1 }
            || metadata.payload_bytes < 5
            || wire_bytes + 40 > usize::from(self.policy.mtu)
            || (metadata.kind == FinalKind::Data && self.half && (self.lane == 0) == self.client)
        {
            return Err(Error::Proof);
        }
        let f = self.fence.as_ref().ok_or(Error::Proof)?;
        let offset = crate::handoff::pairing::packet::sequence::position(
            f.peer,
            metadata.sequence,
            f.retired,
        )
        .ok_or(Error::Proof)?;
        let retired = crate::handoff::pairing::packet::sequence::position(
            f.local,
            metadata.acknowledgment,
            f.sent,
        )
        .ok_or(Error::Proof)?;
        let end = offset
            .checked_add(wire_bytes as u64)
            .ok_or(Error::Exhausted)?;
        let right = f
            .retired
            .checked_add(f.local_horizon)
            .ok_or(Error::Exhausted)?;
        let reserve = metadata.kind.reserve() * (u64::from(self.policy.mtu) - 40);
        if end > right.saturating_sub(reserve)
            || end.saturating_add(f.local_horizon) < f.retired
            || retired > f.sent
            || metadata.window
                != u16::try_from(f.peer_horizon >> f.peer_scale).map_err(|_| Error::Proof)?
        {
            return Err(Error::Proof);
        }
        self.ranges
            .validate(offset, end, f.retired.max(end), f.local_horizon)?;
        Ok(())
    }
    pub(in crate::handoff::pairing::packet) fn commit_final(
        &mut self,
        metadata: FinalMetadata,
    ) -> Result<u64, Error> {
        self.validate_final(metadata)?;
        let wire_bytes = u64::from(metadata.payload_bytes) + self.tls_record_overhead() as u64;
        let f = self.fence.as_mut().ok_or(Error::Proof)?;
        let offset = crate::handoff::pairing::packet::sequence::position(
            f.peer,
            metadata.sequence,
            f.retired,
        )
        .ok_or(Error::Proof)?;
        let end = offset + wire_bytes;
        self.ranges
            .commit(offset, end, f.retired.max(end), f.local_horizon)?;
        f.retired = f.retired.max(end);
        if metadata.kind != FinalKind::Data {
            let acknowledged = crate::handoff::pairing::packet::sequence::position(
                f.local,
                metadata.acknowledgment,
                f.sent,
            )
            .ok_or(Error::Proof)?;
            f.peer_retired = f.peer_retired.max(acknowledged);
        }
        Ok(f.retired)
    }
    pub(in crate::handoff::pairing::packet) fn reject_final_preflight(
        &mut self,
        metadata: FinalMetadata,
    ) -> Result<(), Error> {
        self.candidate_counters[usize::from(candidate_class(metadata.kind))]
            .preflight_rejected
            .record(metadata.payload_bytes());
        self.reject()
    }
    pub(in crate::handoff::pairing::packet) fn reject_final_verdict(
        &mut self,
        metadata: FinalMetadata,
    ) -> Result<(), Error> {
        self.candidate_counters[usize::from(candidate_class(metadata.kind))]
            .verifier_rejected
            .record(metadata.payload_bytes());
        self.reject()
    }
    pub(in crate::handoff::pairing::packet) fn accept_final_verdict(
        &mut self,
        metadata: FinalMetadata,
    ) {
        self.candidate_counters[usize::from(candidate_class(metadata.kind))]
            .accepted
            .record(metadata.payload_bytes());
    }
}

//! Exact same-channel context lookup for the negotiated native-IP grammar.
use super::*;

#[derive(Clone, Default)]
pub(super) struct AnchorHistory {
    retired: [Option<(RecordId, aligned_body::DecoderState)>;
        aligned_body::MAX_ANCHOR_DISTANCE as usize],
}
impl AnchorHistory {
    pub(super) fn remember(&mut self, id: RecordId, header: aligned_body::DecoderState) {
        // At ordered retirement, a colliding older ID can no longer be named
        // by any later record within the wire distance bound.
        let index = (id.0 % self.retired.len() as u64) as usize;
        self.retired[index] = Some((id, header));
    }
    fn get(&self, id: RecordId) -> Option<&aligned_body::DecoderState> {
        self.retired[(id.0 % self.retired.len() as u64) as usize]
            .as_ref()
            .filter(|(stored, _)| *stored == id)
            .map(|(_, header)| header)
    }
}

fn target(record: RecordId, body: &[u8]) -> Result<RecordId, Error> {
    let (distance, _) = aligned_body::fixed_anchor_parts(body).map_err(|_| Error::Malformed)?;
    record
        .0
        .checked_sub(u64::from(distance))
        .map(RecordId)
        .ok_or(Error::Malformed)
}

pub(super) fn validate_tag(
    mode: ReceiverMode,
    record: RecordId,
    body: &[u8],
    complete: bool,
) -> Result<(), Error> {
    let tag = *body.first().ok_or(Error::Malformed)?;
    if tag == aligned_body::FIXED_ANCHOR_TAG {
        if mode != ReceiverMode::FixedIpAnchors {
            return Err(Error::Malformed);
        }
        if complete {
            target(record, body)?;
        }
    } else if mode == ReceiverMode::FixedIpAnchors && !matches!(tag, 2 | 8) {
        return Err(Error::Malformed);
    }
    Ok(())
}

impl Receiver {
    fn live_anchor(&self, channel: ChannelId, id: RecordId) -> Option<usize> {
        let pos = self.record_position(channel, id).ok()?;
        let slot = usize::from(self.ordered_slots[pos]);
        let record = self.records[slot].as_ref()?;
        (record.complete() && record.bytes.first() == Some(&8)).then_some(slot)
    }

    pub(super) fn fixed_anchor_available(&self, entry: &Record) -> Result<bool, Error> {
        let id = target(entry.id, &entry.bytes)?;
        Ok(self.anchors[usize::from(entry.channel.0)].get(id).is_some()
            || self.live_anchor(entry.channel, id).is_some())
    }

    pub(super) fn stage_fixed_anchor(
        &mut self,
        slot: usize,
        remaining: &mut usize,
    ) -> Result<bool, Error> {
        let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
        if entry.early_delivered || entry.bytes.first() != Some(&aligned_body::FIXED_ANCHOR_TAG) {
            return Ok(true);
        }
        let id = target(entry.id, &entry.bytes)?;
        let channel = entry.channel;
        let index = usize::from(channel.0);
        if let Some(header) = self.anchors[index].get(id) {
            self.staged.restore(header.clone());
            return Ok(true);
        }
        let Some(anchor_slot) = self.live_anchor(channel, id) else {
            // Early selection waits for the exact anchor. At the channel head,
            // its older ID was already retired and cannot become available later.
            self.failure = Some(Error::Malformed);
            return Err(Error::Malformed);
        };
        if let Some(p) = &self.channels[index].preview
            && p.anchor == id
            && p.last == id
        {
            self.staged.restore(p.header.clone());
        } else {
            self.decode_slot(anchor_slot)?;
            self.touch_channel(index)?;
            self.channels[index].preview = Some(Preview::from_anchor(id, self.staged.checkpoint()));
            *remaining -= 1;
        }
        Ok(*remaining != 0)
    }
}

//! Bounded lookahead from independent, authenticated native-IP context records.
use super::*;

#[derive(Clone)]
pub(super) struct Preview {
    anchor: RecordId,
    last: RecordId,
    header: aligned_body::DecoderState,
}

impl Receiver {
    // Find the first eligible body and, for a delta, the complete reset chain
    // that gives it an unambiguous header. A missing record or fragment cuts
    // the chain. Both identity order and occupancy are bounded by admission.
    pub(super) fn select_record(
        &self,
        channel: ChannelId,
        expected: RecordId,
        selection: &EarlySelection<'_>,
    ) -> Result<Option<(usize, Option<usize>)>, Error> {
        let start = self
            .record_position(channel, expected)
            .unwrap_or_else(|i| i);
        let packets = matches!(
            selection,
            EarlySelection::Reevaluated {
                complete_packets: true,
                ..
            }
        );
        let mut anchor = None;
        let mut next = None;
        for position in start..self.ordered_slots.len() {
            let entry = self.indexed_record(position)?;
            if entry.channel != channel {
                break;
            }
            if entry.id == expected && entry.complete() {
                return Ok(Some((position, None)));
            }
            if matches!(selection, EarlySelection::Ordered)
                || (!packets && self.limits.body.independent_short_frame_bytes == 0)
            {
                break;
            }
            if !entry.complete() {
                anchor = None;
                continue;
            }
            if Some(entry.id.0) != next {
                anchor = None;
            }
            next = entry.id.0.checked_add(1);
            if packets && entry.bytes.first() == Some(&8) {
                anchor = Some(position);
                continue;
            }
            if entry.early_delivered {
                continue;
            }
            if entry.defer_early != 0
                && !match selection {
                    EarlySelection::Any => true,
                    EarlySelection::Reevaluated { changed, .. }
                        if entry.defer_early != u64::MAX =>
                    {
                        changed(entry.defer_early)
                    }
                    _ => false,
                }
            {
                continue;
            }
            if entry.independent_short || (packets && independent_length(&entry.bytes).is_some()) {
                return Ok(Some((position, None)));
            }
            if anchor.is_some() {
                return Ok(Some((position, anchor)));
            }
        }
        Ok(None)
    }

    fn indexed_record(&self, position: usize) -> Result<&Record, Error> {
        self.records[usize::from(self.ordered_slots[position])]
            .as_ref()
            .ok_or(Error::Malformed)
    }

    pub(super) fn decode_slot(&mut self, slot: usize) -> Result<aligned_body::Decoded, Error> {
        let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
        self.staged
            .decode_body(&entry.bytes, entry.padding, &mut self.native)
            .map_err(|error| {
                self.failure = Some(Error::Body(error));
                Error::Body(error)
            })
    }

    pub(super) fn cache_preview(
        &mut self,
        channel: usize,
        anchor: usize,
        position: usize,
    ) -> Result<(), Error> {
        let preview = Preview {
            anchor: self.indexed_record(anchor)?.id,
            last: self.indexed_record(position)?.id,
            header: self.staged.checkpoint(),
        };
        self.touch_channel(channel)?;
        self.channels[channel].preview = Some(preview);
        Ok(())
    }

    // At most one header transition per unit of caller work, including after
    // a one-record allowance, channel rotation or a temporarily held frame.
    pub(super) fn stage_prefix(
        &mut self,
        channel: usize,
        anchor: usize,
        target: usize,
        remaining: &mut usize,
    ) -> Result<bool, Error> {
        let start = self.indexed_record(anchor)?.id;
        let goal = self.indexed_record(target)?.id;
        let mut position = anchor;
        if let Some(p) = &self.channels[channel].preview
            && p.anchor == start
            && p.last >= start
            && p.last < goal
        {
            // select_record verified all record IDs in this interval are
            // contiguous. The difference is bounded by the retained slots.
            position += usize::try_from(p.last.0 - start.0 + 1).map_err(|_| Error::Malformed)?;
            self.staged.restore(p.header.clone());
        } else {
            self.staged
                .copy_context_from(&self.channels[channel].decoder);
        }
        while position < target && *remaining != 0 {
            let slot = usize::from(self.ordered_slots[position]);
            self.decode_slot(slot)?;
            *remaining -= 1;
            if *remaining == 0 {
                self.cache_preview(channel, anchor, position)?;
                return Ok(false);
            }
            position += 1;
        }
        Ok(true)
    }
}

//! Bounded lookahead from independent, authenticated native-IP context records.
use super::*;

#[derive(Clone)]
pub(super) struct Preview {
    pub(super) anchor: RecordId,
    pub(super) last: RecordId,
    pub(super) header: aligned_body::DecoderState,
}
impl Preview {
    pub(super) fn from_anchor(anchor: RecordId, header: aligned_body::DecoderState) -> Self {
        Self {
            anchor,
            last: anchor,
            header,
        }
    }
}

pub(super) enum RecordSelection {
    Selected {
        position: usize,
        anchor: Option<usize>,
        cache: Option<ScanPrefixCache>,
    },
    Idle(ScanPrefixCache),
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
    ) -> Result<RecordSelection, Error> {
        let start = self
            .record_position(channel, expected)
            .unwrap_or_else(|i| i);
        let (packets, check_head, reevaluated) = match selection {
            EarlySelection::Reevaluated {
                complete_packets,
                check_head,
                ..
            } => (*complete_packets, *check_head, true),
            _ => (false, false, false),
        };
        // Step 1: always inspect the channel head at `start` first.
        let mut scan_pos = start;
        if let Some(entry) = (start < self.ordered_slots.len())
            .then(|| self.indexed_record(start))
            .transpose()?
            && entry.channel == channel
            && entry.id == expected
        {
            if entry.complete() {
                if entry.defer_head
                    && let EarlySelection::Reevaluated {
                        changed,
                        check_head: true,
                        ..
                    } = selection
                    && !changed(entry.defer_early)
                {
                } else {
                    return Ok(RecordSelection::Selected {
                        position: start,
                        anchor: None,
                        cache: None,
                    });
                }
            }
            scan_pos = start + 1;
        }
        if matches!(selection, EarlySelection::Ordered)
            || (!packets && self.limits.body.independent_short_frame_bytes == 0)
        {
            return Ok(RecordSelection::Idle(ScanPrefixCache::None));
        }

        let mut tokens = [0u64; 8];
        let mut token_count = 0usize;
        let mut cacheable = reevaluated;
        let mut skip_floor = expected.0.checked_add(1).map(RecordId);

        // Step 2: if a cached ineligible prefix strictly past `expected` still
        // has all wait tokens unchanged, binary-search jump past it in O(log N).
        let index = usize::from(channel.0);
        if let (
            EarlySelection::Reevaluated { changed, .. },
            ScanPrefixCache::Reevaluated {
                complete_packets: cached_packets,
                check_head: cached_head,
                skip_to,
                count,
                tokens: cached_tokens,
            },
        ) = (selection, self.channels[index].scan_cache)
            && packets == cached_packets
            && check_head == cached_head
            && cached_tokens[..usize::from(count)]
                .iter()
                .all(|&t| !changed(t))
        {
            tokens = cached_tokens;
            token_count = usize::from(count);
            skip_floor = skip_to;
            match skip_to {
                None => {
                    return Ok(RecordSelection::Idle(self.channels[index].scan_cache));
                }
                Some(resume_id) => {
                    if scan_pos < self.ordered_slots.len() {
                        let rel = self.ordered_slots[scan_pos..].binary_search_by_key(
                            &Some((channel.0, resume_id)),
                            |slot| {
                                self.records[usize::from(*slot)]
                                    .as_ref()
                                    .map(|r| (r.channel.0, r.id))
                            },
                        );
                        scan_pos += match rel {
                            Ok(i) | Err(i) => i,
                        };
                    }
                }
            }
        }

        let mut anchor = None;
        let mut next = None;
        let mut last_ineligible: Option<RecordId> = None;
        for position in scan_pos..self.ordered_slots.len() {
            let entry = self.indexed_record(position)?;
            if entry.channel != channel {
                break;
            }
            // A fixed-anchor delta names its own context. A prior native commit
            // leaves only ordered retirement work for this row at the head.
            if self.mode == ReceiverMode::FixedIpAnchors && entry.early_delivered {
                last_ineligible = Some(entry.id);
                continue;
            }
            if !entry.complete() {
                anchor = None;
                last_ineligible = Some(entry.id);
                continue;
            }
            if Some(entry.id.0) != next {
                anchor = None;
            }
            next = entry.id.0.checked_add(1);
            if self.mode != ReceiverMode::FixedIpAnchors
                && packets
                && entry.bytes.first() == Some(&8)
            {
                anchor = Some(position);
                continue;
            }
            if entry.early_delivered {
                if anchor.is_none() {
                    last_ineligible = Some(entry.id);
                }
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
                if cacheable
                    && entry.defer_early != u64::MAX
                    && !tokens[..token_count].contains(&entry.defer_early)
                {
                    if token_count < tokens.len() {
                        tokens[token_count] = entry.defer_early;
                        token_count += 1;
                    } else {
                        cacheable = false;
                    }
                }
                if anchor.is_none() {
                    last_ineligible = Some(entry.id);
                }
                continue;
            }
            let prefix_cache =
                (cacheable && anchor.is_none()).then_some(ScanPrefixCache::Reevaluated {
                    complete_packets: packets,
                    check_head,
                    skip_to: Some(entry.id),
                    count: token_count as u8,
                    tokens,
                });
            if entry.independent_short || (packets && independent_length(&entry.bytes).is_some()) {
                return Ok(RecordSelection::Selected {
                    position,
                    anchor: None,
                    cache: prefix_cache,
                });
            }
            if self.mode == ReceiverMode::FixedIpAnchors {
                if packets
                    && entry.bytes.first() == Some(&aligned_body::FIXED_ANCHOR_TAG)
                    && self.fixed_anchor_available(entry)?
                {
                    return Ok(RecordSelection::Selected {
                        position,
                        anchor: None,
                        cache: prefix_cache,
                    });
                }
                last_ineligible = Some(entry.id);
            } else if anchor.is_some() {
                return Ok(RecordSelection::Selected {
                    position,
                    anchor,
                    cache: None,
                });
            } else {
                last_ineligible = Some(entry.id);
            }
        }
        let cache = if cacheable && anchor.is_none() {
            let skip_to = match last_ineligible {
                Some(id) => id.0.checked_add(1).map(RecordId),
                None => skip_floor,
            };
            ScanPrefixCache::Reevaluated {
                complete_packets: packets,
                check_head,
                skip_to,
                count: token_count as u8,
                tokens,
            }
        } else {
            ScanPrefixCache::None
        };
        Ok(RecordSelection::Idle(cache))
    }

    fn indexed_record(&self, position: usize) -> Result<&Record, Error> {
        self.records[usize::from(self.ordered_slots[position])]
            .as_ref()
            .ok_or(Error::Malformed)
    }

    pub(super) fn decode_slot(&mut self, slot: usize) -> Result<aligned_body::Decoded, Error> {
        let entry = self.records[slot].as_ref().ok_or(Error::Malformed)?;
        let decoded = if self.mode == ReceiverMode::FixedIpAnchors
            && entry.bytes.first() == Some(&aligned_body::FIXED_ANCHOR_TAG)
        {
            self.staged
                .decode_fixed_anchor_body(&entry.bytes, entry.padding, &mut self.native)
        } else {
            self.staged
                .decode_body(&entry.bytes, entry.padding, &mut self.native)
        };
        decoded.map_err(|error| {
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

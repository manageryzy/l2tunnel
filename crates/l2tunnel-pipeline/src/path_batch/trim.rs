use super::*;

impl PathBatcher {
    /// Filter entries before the next preparation. The callback receives each old position and
    /// its new position if retained, in wire order. A frozen head is never modified. Removing
    /// the complete head reuses its unissued sequence for the second buffer without delaying it.
    pub fn retain_due(
        &mut self,
        path: PathId,
        now: Duration,
        mut keep: impl FnMut(EntryPosition, EntryPosition, u64, u8) -> bool,
    ) -> Result<(), Error> {
        let lane = self.lane_mut(path)?;
        lane.observe(now)?;
        if lane.frozen_data_len.is_some() {
            return Ok(());
        }
        if lane.ready.count != 0 {
            lane.ready.retain(path, lane.next, &mut keep)?;
            if lane.ready.count != 0 {
                return Ok(());
            }
            // A prebuilt following batch now owns the unissued sequence. Remap all
            // local positions even when its own hold deadline has not arrived yet.
            if lane.open.count != 0 {
                lane.open.retain(path, lane.next, &mut keep)?;
            }
        } else if lane.due() {
            lane.open.retain(path, lane.next, &mut keep)?;
        }
        Ok(())
    }
}

impl Buffer {
    fn retain(
        &mut self,
        path: PathId,
        sequence: u64,
        keep: &mut impl FnMut(EntryPosition, EntryPosition, u64, u8) -> bool,
    ) -> Result<(), Error> {
        let old = BatchId {
            path,
            sequence: self.sequence,
        };
        let new = BatchId { path, sequence };
        let mut src = wire::header_len(self.sequence);
        let header = wire::header_len(sequence);
        let mut dst = header;
        let mut count = 0;
        for index in 0..self.count {
            let mut tail = &self.bytes[src..];
            let entry = wire::shard(path, &mut tail)?;
            let end = self.bytes.len() - tail.len();
            if keep(
                EntryPosition { batch: old, index },
                EntryPosition {
                    batch: new,
                    index: count,
                },
                entry.generation,
                entry.ordinal,
            ) {
                if dst != src {
                    self.bytes.copy_within(src..end, dst);
                }
                dst += end - src;
                count += 1;
            }
            src = end;
        }
        if count == 0 {
            self.clear();
            return Ok(());
        }
        if self.sequence != sequence {
            let mut n = sequence;
            for b in &mut self.bytes[2..header - 1] {
                *b = (n as u8 & 127) | if n >= 128 { 128 } else { 0 };
                n >>= 7;
            }
        }
        self.sequence = sequence;
        self.count = count;
        self.bytes[header - 1] = count;
        self.bytes.truncate(dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim_reuses_unissued_sequence_across_varint_width_and_keeps_frozen_ack() -> Result<(), Error>
    {
        let path = PathId::new(0)?;
        let cfg = PathConfig {
            mtu: 1500,
            outer_bytes: 49,
            max_hold: Duration::ZERO,
            max_entries: 2,
        };
        let mut tx = PathBatcher::new(&[cfg])?;
        tx.lanes[0].next = 127;
        let make = |generation| Shard {
            generation,
            ordinal: 0,
            bytes: b"a",
        };
        let t = Duration::ZERO;
        for g in 0..4 {
            tx.enqueue(path, t, None, make(g))?;
        }
        let mut moves = vec![];
        tx.retain_due(path, t, |old, new, g, _| {
            moves.push((
                old.batch.sequence(),
                old.index,
                new.batch.sequence(),
                new.index,
            ));
            g == 3
        })?;
        assert_eq!(
            moves,
            [
                (127, 0, 127, 0),
                (127, 1, 127, 0),
                (128, 0, 127, 0),
                (128, 1, 127, 0)
            ]
        );
        let ack = &[0xa1, 1, 0, 0, 1, 0][..];
        let ready = tx.prepare(path, t, Some(ack))?.ok_or(Error::StaleReceipt)?;
        let (id, frozen) = (ready.id, ready.bytes.to_vec());
        let decoded = cfg.decode(path, &frozen)?;
        assert_eq!(decoded.sequence, 127);
        assert_eq!(decoded.ack, Some(ack));
        assert_eq!(decoded.entries().collect::<Vec<_>>(), [make(3)]);
        tx.enqueue(path, t, None, make(4))?;
        let mut callback_called = false;
        tx.retain_due(path, t, |_, _, _, _| {
            callback_called = true;
            true
        })?;
        assert!(!callback_called);
        assert_eq!(tx.prepared_bytes(id)?, frozen);
        tx.confirm(id)?;
        assert_eq!(
            tx.prepare(path, t, None)?
                .ok_or(Error::StaleReceipt)?
                .id
                .sequence(),
            128
        );
        Ok(())
    }
}

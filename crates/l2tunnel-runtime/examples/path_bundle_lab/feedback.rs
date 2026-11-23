use super::*;
use l2tunnel_pipeline::path_ack::{AckBatch, AckReceiver, Opportunity};
use std::rc::Rc;

/// One bounded copy flight. A blocked path retains its exact body while siblings can pay.
pub struct RequestCopies {
    n: u8,
    queue: VecDeque<(u8, u8, Rc<[u8]>)>,
}
impl RequestCopies {
    pub fn new(n: u8) -> Self {
        Self {
            n,
            queue: VecDeque::with_capacity(usize::from(n)),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
    pub fn has_ready(&self, available: impl Fn(u8) -> bool) -> bool {
        self.queue.iter().any(|(path, _, _)| available(*path))
    }
    pub fn schedule(&mut self, start: u8, copies: u8, body: Vec<u8>) -> u8 {
        let body: Rc<[u8]> = body.into();
        for copy in 0..copies {
            self.queue
                .push_back((rotate(start, copy, self.n), copy, Rc::clone(&body)));
        }
        rotate(start, copies, self.n)
    }
    pub fn take_ready(
        &mut self,
        mut available: impl FnMut(u8) -> bool,
    ) -> Option<(u8, u8, Rc<[u8]>)> {
        let position = self
            .queue
            .iter()
            .position(|(path, _, _)| available(*path))?;
        self.queue.remove(position)
    }
}

#[derive(Clone)]
pub struct Receipt {
    pub bytes: Vec<u8>,
    round: u64,
    tokens: Vec<(usize, u64)>,
    delivered: u64,
    next_cursor: u64,
}

pub struct Book {
    lanes: Vec<AckReceiver>,
    delivered: u64,
    reported: u64,
    oldest: Option<u64>,
    cursor: u64,
    round: u64,
    in_flight: Option<Receipt>,
    oldest_after_claim: Option<u64>,
    rescan: bool,
}

impl Book {
    pub fn new(n: u8) -> Result<Self> {
        Self::configured(n, None)
    }
    pub fn with_selective_repeat(n: u8, repeat_delay: u64) -> Result<Self> {
        Self::configured(n, Some(repeat_delay))
    }
    fn configured(n: u8, repeat: Option<u64>) -> Result<Self> {
        let lanes = (0..n)
            .map(|i| match repeat {
                Some(delay) => AckReceiver::with_selective_repeat(&[i], 256, 16, 1_000, delay),
                None => AckReceiver::new(&[i], 256, 16, 1_000),
            })
            .collect::<std::result::Result<_, _>>()?;
        Ok(Self {
            lanes,
            delivered: 0,
            reported: 0,
            oldest: None,
            cursor: 0,
            round: 0,
            in_flight: None,
            oldest_after_claim: None,
            rescan: false,
        })
    }
    pub fn observe(&mut self, path: u8, sequence: u64, now: u64) -> Result<()> {
        self.lanes[usize::from(path)].observe_data(path, sequence, now)?;
        Ok(())
    }
    pub fn native(&mut self, gid: u64, now: u64) {
        self.delivered += 1;
        self.oldest.get_or_insert(now);
        // A frozen page may advance the cursor beyond a newly delivered group.
        if gid < self.cursor || self.in_flight.as_ref().is_some_and(|r| gid < r.next_cursor) {
            self.rescan = true;
        }
        if self.in_flight.is_some() {
            self.oldest_after_claim.get_or_insert(now);
        }
    }
    pub fn due(&self, now: u64) -> Option<u64> {
        let logical = if self.delivered - self.reported >= 16 {
            Some(now)
        } else {
            self.oldest.map(|v| v + 1_000)
        };
        self.lanes
            .iter()
            .filter_map(AckReceiver::next_deadline)
            .chain(logical)
            .min()
    }
    pub fn prepare(&mut self, rx: &Receiver, now: u64) -> Result<Option<Receipt>> {
        if let Some(held) = &self.in_flight {
            return Ok(Some(held.clone()));
        }
        if self.due(now).is_none() {
            return Ok(None);
        }
        let mut selected: Vec<_> = self
            .lanes
            .iter()
            .enumerate()
            .filter(|(_, r)| r.can_piggyback(now))
            .filter_map(|(i, r)| r.next_deadline().map(|t| (t, i)))
            .collect();
        selected.sort_unstable();
        selected.truncate(4);
        selected.sort_unstable_by_key(|v| v.1);
        if selected.is_empty() && self.oldest.is_none() {
            return Ok(None);
        }
        let mut blocks = Vec::with_capacity(5);
        let mut tokens = Vec::with_capacity(4);
        for (_, i) in selected {
            let ack = self.lanes[i]
                .prepare(now, Opportunity::Piggyback)?
                .ok_or("lost physical ACK")?;
            blocks.extend_from_slice(ack.batch().blocks());
            tokens.push((i, ack.token()));
        }
        let (logical, cont) = rx.confirmation(self.cursor)?;
        blocks.push(logical);
        let batch = AckBatch::new(blocks)?;
        let mut bytes = vec![0; batch.wire_len()];
        batch.encode(&mut bytes)?;
        Ok(Some(Receipt {
            bytes,
            round: self.round,
            tokens,
            delivered: self.delivered,
            next_cursor: cont.unwrap_or(0),
        }))
    }
    pub fn claim(&mut self, receipt: &Receipt) {
        if self.in_flight.is_none() {
            self.in_flight = Some(receipt.clone());
        }
    }
    pub fn paid(&mut self, receipt: Receipt, now: u64) -> Result<()> {
        // Several paths may carry this immutable snapshot after a blocked write.
        // Charge every datagram but retire its logical receipt on the first success.
        if receipt.round < self.round {
            return Ok(());
        }
        if receipt.round != self.round || self.in_flight.is_none() {
            return Err("unexpected ACK payment".into());
        }
        let next_round = self.round.checked_add(1).ok_or("exhausted ACK rounds")?;
        for (i, t) in receipt.tokens {
            self.lanes[i].confirm_paid(t, now, now)?;
        }
        self.round = next_round;
        self.in_flight = None;
        self.reported = receipt.delivered;
        let finished = receipt.next_cursor == 0;
        self.oldest = self
            .oldest_after_claim
            .take()
            .or((!finished || self.rescan).then_some(now));
        if finished {
            self.rescan = false;
        }
        self.cursor = receipt.next_cursor;
        Ok(())
    }
}

// Ordered deadlines and per-group state stay below the facade's authenticated receive horizon.
struct Gap {
    due: u64,
    start: u8,
    first_request: bool,
}

pub struct Gaps {
    n: u8,
    max_rows: usize,
    due: BTreeSet<(u64, u64)>,
    groups: BTreeMap<u64, Gap>,
    extra_threshold: Option<u8>,
    pub first_partial_extra_rows: u64,
}

impl Gaps {
    pub fn new(n: u8, plaintext: usize) -> Self {
        Self {
            n,
            max_rows: 32.min((plaintext - 2) / (10 + usize::from(n).div_ceil(8))),
            due: BTreeSet::new(),
            groups: BTreeMap::new(),
            extra_threshold: None,
            first_partial_extra_rows: 0,
        }
    }
    #[cfg(test)]
    pub fn with_first_partial_extra(mut self, threshold: Option<u8>) -> Self {
        self.extra_threshold = threshold.filter(|&k| k < self.n);
        self
    }
    pub fn expose(&mut self, range: std::ops::Range<u64>, now: u64) {
        for id in range {
            let due = now + 1_000;
            self.groups.insert(
                id,
                Gap {
                    due,
                    start: 0,
                    first_request: true,
                },
            );
            self.due.insert((due, id));
        }
    }
    pub fn remove(&mut self, id: u64) {
        if let Some(gap) = self.groups.remove(&id) {
            self.due.remove(&(gap.due, id));
        }
    }
    pub fn wake(&self) -> Option<u64> {
        self.due.first().map(|v| v.0)
    }
    pub fn request(&mut self, rx: &Receiver, now: u64) -> Result<Option<Vec<u8>>> {
        let mut rows = Vec::new();
        while rows.len() < self.max_rows && self.due.first().is_some_and(|(due, _)| *due <= now) {
            let (_, id) = self.due.pop_first().ok_or("lost gap clock")?;
            let mut gap = self.groups.remove(&id).ok_or("lost gap")?;
            let mut ordinals = rx.missing_from(id, gap.start);
            if ordinals.is_empty() {
                continue;
            }
            // Keep the ordinary rotation on repeat requests, even if the first row was extended.
            gap.start = rotate(gap.start, ordinals.len() as u8, self.n);
            if gap.first_request
                && self
                    .extra_threshold
                    .is_some_and(|k| (2..usize::from(k)).contains(&ordinals.len()))
                && let Some(&last) = ordinals.last()
                && let Some(extra) = rx.missing_from(id, rotate(last, 1, self.n)).first()
                && !ordinals.contains(extra)
            {
                ordinals.push(*extra);
                self.first_partial_extra_rows += 1;
            }
            gap.first_request = false;
            gap.due = now + 70_000;
            self.due.insert((gap.due, id));
            self.groups.insert(id, gap);
            rows.push((id, ordinals));
        }
        if rows.is_empty() {
            return Ok(None);
        }
        rows.sort_unstable_by_key(|r| r.0);
        let names = ShardRequest::new(self.n, rows)?;
        let mut bytes = vec![0; names.wire_len()];
        names.encode(&mut bytes)?;
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2tunnel_fec::{ChannelId, Direction, Epoch, FecContext, SessionId};

    #[test]
    fn first_partial_extra_names_one_distinct_member_without_changing_later_requests() -> Result<()>
    {
        let domain = FecContext {
            session: SessionId([1; 16]),
            channel: ChannelId(0),
            epoch: Epoch(0),
            direction: Direction::ClientToServer,
        };
        for (n, k, seen, expected, extended) in [
            (6, 5, vec![0, 1, 3], vec![2, 4, 5], true),
            (6, 5, vec![1], vec![0, 2, 3, 4, 5], true),
            (6, 5, vec![0, 1, 3, 5], vec![2], false),
            (5, 5, vec![0, 1, 3], vec![2, 4], false),
        ] {
            let mut rx = Receiver::new(domain, n, k, 500, 800, 16)?;
            let shards =
                l2tunnel_fec::path_shards::Profile::new(n, k, 500, 800)?.encode(b"fixture")?;
            for ordinal in seen {
                rx.accept(
                    domain,
                    l2tunnel_pipeline::path_batch::Shard {
                        generation: 1,
                        ordinal,
                        bytes: &shards[usize::from(ordinal)],
                    },
                )?;
            }
            let mut ordinary = Gaps::new(n, 1200);
            let mut extra = Gaps::new(n, 1200).with_first_partial_extra(Some(k));
            ordinary.expose(0..2, 0);
            extra.expose(0..2, 0);
            let baseline = ordinary.request(&rx, 1000)?.ok_or("missing baseline")?;
            let added = extra.request(&rx, 1000)?.ok_or("missing first request")?;
            let actual = ShardRequest::decode(n, &added)?;
            assert_eq!(actual.rows()[0], (0, (0..k).collect())); // Completely unseen old gap.
            assert_eq!(actual.rows()[1], (1, expected));
            assert_eq!(extra.first_partial_extra_rows, u64::from(extended));
            assert_eq!(baseline == added, !extended);
            assert_eq!(extra.request(&rx, 70_999)?, None);
            assert_eq!(extra.request(&rx, 71_000)?, ordinary.request(&rx, 71_000)?);
            assert_eq!(extra.first_partial_extra_rows, u64::from(extended));
        }
        Ok(())
    }

    fn commit(
        rx: &mut Receiver,
        book: &mut Book,
        domain: FecContext,
        gid: u64,
        now: u64,
    ) -> Result<()> {
        let profile = l2tunnel_fec::path_shards::Profile::new(1, 1, 32, 64)?;
        let parts = profile.encode(b"native")?;
        assert!(rx.accept(
            domain,
            l2tunnel_pipeline::path_batch::Shard {
                generation: gid,
                ordinal: 0,
                bytes: &parts[0]
            }
        )?);
        assert!(rx.commit(gid)?);
        book.native(gid, now);
        Ok(())
    }
    #[test]
    fn one_quiet_probe_reannounces_lost_native_receipt_without_redelivery() -> Result<()> {
        let domain = FecContext {
            session: SessionId([3; 16]),
            channel: ChannelId(0),
            epoch: Epoch(0),
            direction: Direction::ClientToServer,
        };
        let mut rx = Receiver::new(domain, 1, 1, 32, 64, 32)?;
        let mut book = Book::new(1)?;
        commit(&mut rx, &mut book, domain, 0, 0)?;
        let first = book.prepare(&rx, 1_000)?.ok_or("first native receipt")?;
        book.claim(&first);
        book.paid(first, 1_000)?; // The wire drops this paid receipt.
        assert!(book.due(140_000).is_none());
        let profile = l2tunnel_fec::path_shards::Profile::new(1, 1, 32, 64)?;
        let parts = profile.encode(b"native")?;
        book.observe(0, 0, 140_000)?;
        assert!(!rx.accept(
            domain,
            l2tunnel_pipeline::path_batch::Shard {
                generation: 0,
                ordinal: 0,
                bytes: &parts[0],
            }
        )?);
        assert!(rx.ready(0).is_none());
        let again = book
            .prepare(&rx, 141_000)?
            .ok_or("repeated custody receipt")?;
        let batch = AckBatch::decode(&again.bytes)?;
        let native = batch.blocks().last().ok_or("missing logical block")?;
        assert_eq!(native.path(), LOGICAL_GROUP);
        assert!(native.acknowledges(0));
        Ok(())
    }

    #[test]
    fn future_physical_repeat_does_not_delay_or_manufacture_logical_feedback() -> Result<()> {
        let domain = FecContext {
            session: SessionId([2; 16]),
            channel: ChannelId(0),
            epoch: Epoch(0),
            direction: Direction::ClientToServer,
        };
        let mut rx = Receiver::new(domain, 1, 1, 32, 64, 32)?;
        let mut book = Book::with_selective_repeat(1, 8_000)?;
        book.observe(0, 5, 0)?;
        let initial = book.prepare(&rx, 1)?.ok_or("missing selective receipt")?;
        book.claim(&initial);
        book.paid(initial, 2)?;
        assert_eq!(book.due(3), Some(8_002));
        assert!(book.prepare(&rx, 3)?.is_none());
        commit(&mut rx, &mut book, domain, 0, 100)?;
        let native = book
            .prepare(&rx, 1_100)?
            .ok_or("logical receipt delayed behind repeat")?;
        let b = AckBatch::decode(&native.bytes)?;
        assert_eq!(b.blocks().len(), 1);
        assert!(b.blocks()[0].acknowledges(0));
        assert_eq!(b.blocks()[0].path(), 255);
        book.claim(&native);
        book.paid(native, 1_101)?;
        let repeat = book
            .prepare(&rx, 8_002)?
            .ok_or("physical repeat disappeared")?;
        assert!(AckBatch::decode(&repeat.bytes)?.blocks()[0].acknowledges(5));
        book.claim(&repeat);
        book.paid(repeat, 8_002)?;
        assert_eq!(book.due(8_002), None);
        Ok(())
    }

    #[test]
    fn newly_delivered_behind_cursor_is_reported_after_the_last_page_without_new_traffic()
    -> Result<()> {
        for phase in 0..3 {
            let domain = FecContext {
                session: SessionId([1; 16]),
                channel: ChannelId(0),
                epoch: Epoch(0),
                direction: Direction::ClientToServer,
            };
            let mut rx = Receiver::new(domain, 1, 1, 32, 64, 32)?;
            let mut book = Book::new(1)?;
            for g in (1..20).step_by(2) {
                commit(&mut rx, &mut book, domain, g, 0)?;
            }
            let first = book.prepare(&rx, 1)?.ok_or("missing first page")?;
            assert_eq!(first.next_cursor, 17);
            book.claim(&first);
            if phase == 0 {
                commit(&mut rx, &mut book, domain, 2, 2)?;
            }
            book.paid(first, 3)?;
            if phase == 1 {
                commit(&mut rx, &mut book, domain, 2, 4)?;
            }
            let last = book.prepare(&rx, 5)?.ok_or("missing last page")?;
            assert_eq!(last.next_cursor, 0);
            assert!(!AckBatch::decode(&last.bytes)?.blocks()[0].acknowledges(2));
            book.claim(&last);
            if phase == 2 {
                commit(&mut rx, &mut book, domain, 2, 6)?;
            }
            book.paid(last, 7)?;
            let mut at = book.due(8).ok_or("unreported group lost its deadline")?;
            let mut seen = false;
            for _ in 0..2 {
                let page = book.prepare(&rx, at)?.ok_or("missing rescan")?;
                seen |= AckBatch::decode(&page.bytes)?.blocks()[0].acknowledges(2);
                book.claim(&page);
                book.paid(page, at)?;
                let Some(due) = book.due(at) else { break };
                at = due;
            }
            assert!(seen);
            assert_eq!(book.due(at), None);
        }
        Ok(())
    }

    #[test]
    fn a_blocked_ack_can_be_paid_on_another_path_and_late_payment_preserves_new_work() -> Result<()>
    {
        let domain = FecContext {
            session: SessionId([1; 16]),
            channel: ChannelId(0),
            epoch: Epoch(0),
            direction: Direction::ClientToServer,
        };
        let rx = Receiver::new(domain, 3, 2, 500, 800, 16)?;
        let mut book = Book::new(3)?;
        book.observe(0, 0, 0)?;
        book.native(0, 0);
        let first = book.prepare(&rx, 100)?.ok_or("first receipt")?;
        book.claim(&first);
        book.observe(1, 0, 400)?;
        book.native(1, 400);
        let second = book.prepare(&rx, 1000)?.ok_or("alternate path receipt")?;
        assert_eq!(first.bytes, second.bytes);
        book.claim(&second);
        book.paid(second, 1200)?;
        assert_eq!(book.due(1200), Some(1400));
        book.paid(first, 1300)?;
        let new = book.prepare(&rx, 1400)?.ok_or("next snapshot")?;
        assert_eq!(AckBatch::decode(&new.bytes)?.blocks()[0].path(), 1);
        book.claim(&new);
        book.paid(new, 1400)?;
        assert_eq!(book.due(1400), None);
        Ok(())
    }
}

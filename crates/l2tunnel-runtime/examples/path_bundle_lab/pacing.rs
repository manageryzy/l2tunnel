//! Shared egress budget for a single direction of the isolated multipath lab.
use super::rotate;
use serde::Serialize;
mod checkpoint;
mod frontiers;
use frontiers::Frontiers;

pub(super) const ETHERNET_HEADER: u64 = 14;
pub(super) const MAX_BURST_FRAMES: u8 = 8;
const UNITS_PER_BYTE: u128 = 8_000_000; // bits times microseconds per second

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Ack,
    Request,
    Data,
}

impl Class {
    const ALL: [Self; 3] = [Self::Ack, Self::Request, Self::Data];

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Default, Serialize)]
pub(super) struct Stats {
    paid_ethernet_bytes: u64,
    paid_packets: u64,
    credit_deferrals: u64,
    credit_wait_us: u64,
    reserved_payments: u64,
    reserved_payment_late_us: u64,
    reserved_payment_late_max_us: u64,
    reserved_payments_at_input_checkpoint: u64,
    checkpoint_selections_attempted: u64,
    checkpoint_selections_paid: u64,
    checkpoint_selections_reserved: u64,
    checkpoint_selections_without_handoff: u64,
    checkpoint_no_eligible_work: u64,
    reserved_poll_timeouts: u64,
    reserved_poll_timeout_late_us: u64,
    reserved_poll_timeout_late_max_us: u64,
}

#[derive(Clone, Copy)]
struct Reservation {
    class: Class,
    slot: u8,
    since: u64,
    ready: u64,
}

pub(super) struct Scheduler {
    rate: u64,
    cap: u128,
    credit: u128,
    updated: Option<u64>,
    n: u8,
    turn: usize,
    cursors: [u8; 3],
    blocked: Vec<bool>,
    waiting: Option<Reservation>,
    pub(super) frontiers: Option<Frontiers>,
    pub stats: Stats,
}

impl Scheduler {
    pub fn new(rate: u64, mtu: u16, n: u8, burst_frames: u8) -> super::Result<Self> {
        if !(1..=MAX_BURST_FRAMES).contains(&burst_frames) || rate == 0 || n == 0 {
            return Err("invalid shared pacing configuration".into());
        }
        let frame_bytes = u64::from(mtu) + ETHERNET_HEADER;
        let cap_bytes = frame_bytes
            .checked_mul(u64::from(burst_frames))
            .ok_or("pacing burst capacity overflow")?;
        Ok(Self {
            rate,
            cap: u128::from(cap_bytes) * UNITS_PER_BYTE,
            // Start with exactly one frame, even after an idle startup. Credit
            // for subsequent catch-up accumulates only after the first handoff.
            credit: u128::from(frame_bytes) * UNITS_PER_BYTE,
            updated: None,
            n,
            turn: 0,
            cursors: [0; 3],
            blocked: vec![false; usize::from(n)],
            waiting: None,
            frontiers: None,
            stats: Stats::default(),
        })
    }

    pub fn burst_bytes(&self) -> u64 {
        (self.cap / UNITS_PER_BYTE) as u64
    }

    fn available(&self, now: u64) -> u128 {
        let elapsed = self.updated.map_or(0, |last| now.saturating_sub(last));
        let refill = u128::from(elapsed) * u128::from(self.rate);
        self.credit.saturating_add(refill).min(self.cap)
    }

    pub fn ready_at(&self, now: u64, ip_bytes: usize) -> u64 {
        let charge = (ip_bytes as u128 + u128::from(ETHERNET_HEADER)) * UNITS_PER_BYTE;
        let debt = charge.saturating_sub(self.available(now));
        now.saturating_add(debt.div_ceil(u128::from(self.rate)) as u64)
    }

    pub fn classes(&self) -> [Class; 3] {
        std::array::from_fn(|i| Class::ALL[(self.turn + i) % 3])
    }

    pub fn path(&self, class: Class, offset: u8) -> u8 {
        if class == Class::Data
            && let Some(f) = &self.frontiers
        {
            return rotate(f.ordinary_cursor, offset, self.n);
        }
        rotate(self.cursors[class.index()], offset, self.n)
    }

    pub fn with_original_frontiers(mut self, enabled: bool) -> Self {
        self.frontiers = enabled.then(|| Frontiers::new(self.n));
        self
    }

    pub fn waiting(&self) -> Option<(Class, u8)> {
        self.waiting.map(|r| (r.class, r.slot))
    }

    fn reserve(&mut self, class: Class, slot: u8, now: u64, ready: u64) {
        if self.waiting.is_none() {
            self.stats.credit_deferrals += 1;
            self.waiting = Some(Reservation {
                class,
                slot,
                since: now,
                ready,
            });
        }
    }

    pub fn poll_timeout(&mut self, entered: u64, returned: u64) {
        if let Some(r) = self
            .waiting
            .filter(|r| entered < r.ready && r.ready <= returned)
        {
            let late = returned - r.ready;
            self.stats.reserved_poll_timeouts += 1;
            self.stats.reserved_poll_timeout_late_us += late;
            self.stats.reserved_poll_timeout_late_max_us =
                self.stats.reserved_poll_timeout_late_max_us.max(late);
        }
    }

    fn clear_reservation(&mut self, now: u64) {
        if let Some(r) = self.waiting.take() {
            self.stats.credit_wait_us += now.saturating_sub(r.since);
        }
    }

    pub fn paid(&mut self, class: Class, slot: u8, ip_bytes: usize, now: u64) {
        let bytes = ip_bytes as u64 + ETHERNET_HEADER;
        self.credit = self.available(now) - u128::from(bytes) * UNITS_PER_BYTE;
        self.updated = Some(now);
        self.stats.paid_ethernet_bytes += bytes;
        self.stats.paid_packets += 1;
        if class == Class::Data
            && let Some(f) = &mut self.frontiers
        {
            f.data_paid(slot, self.n);
        }
        if let Some(r) = self.waiting {
            let late = now.saturating_sub(r.ready);
            self.stats.reserved_payments += 1;
            self.stats.reserved_payment_late_us += late;
            self.stats.reserved_payment_late_max_us =
                self.stats.reserved_payment_late_max_us.max(late);
        }
        self.clear_reservation(now);
        self.cursors[class.index()] = rotate(slot, 1, self.n);
        self.turn = (class.index() + 1) % 3;
    }

    pub fn block(&mut self, slot: u8, now: u64) {
        self.blocked[usize::from(slot)] = true;
        if let Some(f) = &mut self.frontiers {
            f.chosen = None;
        }
        self.clear_reservation(now);
    }

    pub fn writable(&mut self, slot: usize) {
        self.blocked[slot] = false;
    }

    pub fn blocked(&self, slot: u8) -> bool {
        self.blocked[usize::from(slot)]
    }

    fn after_idle_scan(
        &self,
        now: u64,
        protocol_due: Option<u64>,
        blocked_head_sizes: impl Iterator<Item = usize>,
        next_partial_wake: impl FnOnce() -> super::Result<Option<u64>>,
    ) -> super::Result<Option<u64>> {
        let mut blocked = 0;
        let mut credit_due = None;
        for bytes in blocked_head_sizes {
            blocked += 1;
            let ready = self.ready_at(now, bytes);
            if ready > now {
                credit_due = Some(credit_due.map_or(ready, |d: u64| d.min(ready)));
            }
        }
        let protocol = if blocked > 0 && protocol_due.is_some_and(|due| due <= now) {
            // The completed scan found no payable work. Only poll can clear a
            // genuine WouldBlock. A funded blocked head requests POLLOUT now.
            if blocked == usize::from(self.n) {
                None
            } else {
                next_partial_wake()?
            }
        } else {
            protocol_due
        };
        Ok(protocol.into_iter().chain(credit_due).min())
    }
}

#[derive(Clone, Copy)]
pub(super) enum Pass {
    Regular,
    Input,
}

enum Attempt {
    Paid,
    Wait,
    Blocked,
}

impl super::Driver {
    // Preserve the chosen large packet while its credit accumulates. A genuinely
    // blocked socket relinquishes that turn without paying or changing frozen bytes.
    fn paced_attempt(&mut self, class: Class, slot: u8) -> super::Result<Attempt> {
        let ip = self.wire[usize::from(slot)]
            .as_ref()
            .ok_or("missing selected wire head")?
            .bytes
            .len()
            + 28;
        if ip > self.path.mtu {
            return Err("frozen datagram exceeds paced IP MTU".into());
        }
        let scheduler = self.pacing.as_mut().ok_or("missing egress budget")?;
        // Staging a batch and sealing its contents may span a credit deadline.
        let now = self.origin.elapsed().as_micros() as u64;
        let ready = scheduler.ready_at(now, ip);
        if ready > now {
            scheduler.reserve(class, slot, now, ready);
            return Ok(Attempt::Wait);
        }
        Ok(if self.send_pending(slot)? {
            Attempt::Paid
        } else {
            Attempt::Blocked
        })
    }

    fn stage_class(&mut self, class: Class, slot: u8, now: u64, pass: Pass) -> super::Result<bool> {
        if let Some(head) = &self.wire[usize::from(slot)] {
            return Ok(head.kind.class() == class);
        }
        match class {
            Class::Data => self.prepare_data(slot, now, pass),
            Class::Ack => {
                if self.ack.due(now).is_none_or(|due| due > now) {
                    return Ok(false);
                }
                self.prepare_ack(slot, now)?;
                Ok(true)
            }
            Class::Request => {
                if self.prepare_path_ready(slot, now)? {
                    return Ok(true);
                }
                if self.requests.is_empty()
                    && let Some(body) = self.gaps.request(&self.rx, now)?
                {
                    self.requests
                        .schedule(slot, self.cfg.a3_request_copies, body);
                }
                if let Some((route, copy, body)) = self.requests.take_ready(|p| p == slot) {
                    self.prepare_request(route, copy, &body, now)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    pub(super) fn paced_step(&mut self, now: u64, pass: Pass) -> super::Result<bool> {
        let s = self.pacing.as_ref().ok_or("missing egress budget")?;
        let classes = s.classes();
        let starts = classes.map(|c| s.path(c, 0));
        if let Some((class, slot)) = s.waiting() {
            match self.paced_attempt(class, slot)? {
                Attempt::Paid => return Ok(true),
                Attempt::Wait => return Ok(false),
                Attempt::Blocked => (),
            }
        }
        for (class, start) in classes.into_iter().zip(starts) {
            if class == Class::Data
                && let Some((slot, gid)) = self.preferred_original(now)?
                && self.stage_preferred_original(slot, gid, now, pass)?
            {
                match self.paced_attempt(class, slot)? {
                    Attempt::Paid => return Ok(true),
                    Attempt::Wait => return Ok(false),
                    Attempt::Blocked => (),
                }
            }
            for offset in 0..self.cfg.n {
                let slot = rotate(start, offset, self.cfg.n);
                if self.pacing.as_ref().is_some_and(|s| s.blocked(slot))
                    || !self.stage_class(class, slot, now, pass)?
                {
                    continue;
                }
                match self.paced_attempt(class, slot)? {
                    Attempt::Paid => return Ok(true),
                    Attempt::Wait => return Ok(false),
                    Attempt::Blocked => (),
                }
            }
        }
        Ok(false)
    }

    pub(super) fn next_deadline(&self, now: u64) -> super::Result<Option<u64>> {
        let Some(s) = &self.pacing else {
            return self.protocol_deadline(now);
        };
        if let Some(r) = s.waiting {
            // All egress shares this immutable head's budget until handoff or
            // WouldBlock. Input and shutdown are still polled.
            return Ok(Some(r.ready));
        }
        let protocol_due = self.protocol_deadline(now)?;
        let blocked = self.wire.iter().enumerate().filter_map(|(i, head)| {
            head.as_ref()
                .filter(|_| s.blocked(i as u8))
                .map(|p| p.bytes.len() + 28)
        });
        s.after_idle_scan(now, protocol_due, blocked, || self.next_partial_wake(now))
    }

    // A stale minimum for a blocked path can mask the next timed event on a
    // healthy one. Keep future deadlines individual. Bound the recheck for
    // components that expose only their own earliest deadline.
    fn next_partial_wake(&self, now: u64) -> super::Result<Option<u64>> {
        let mut next = now.saturating_add(1_000);
        let mut consider = |deadline: Option<u64>| {
            if let Some(at) = deadline.filter(|&at| at > now) {
                next = next.min(at);
            }
        };
        consider(self.recovery.quiet);
        consider(self.recovery.deferred_wake());
        consider(self.ack.due(now));
        consider(self.gaps.wake().filter(|_| self.requests.is_empty()));
        for slot in 0..self.cfg.n {
            if self.wire[usize::from(slot)].is_some() {
                continue;
            }
            if let Some(state) = &self.path_ready {
                consider(state.path_wake(slot, now)?);
            }
            if let Some(ledger) = self.physical.get(usize::from(slot)) {
                if !self.recovery.has_queued_path_repair(slot) || !ledger.can_send() {
                    consider(ledger.next_deadline());
                }
                if !ledger.can_send() {
                    continue;
                }
            }
            consider(
                self.tx
                    .next_wake(super::PathId::new(slot)?)?
                    .map(|t| t.as_micros() as u64),
            );
        }
        Ok(Some(next))
    }

    pub(super) fn want_writable(&self, slot: u8, now: u64) -> bool {
        self.wire[usize::from(slot)].as_ref().is_some_and(|p| {
            self.pacing.as_ref().is_none_or(|s| {
                s.waiting().is_none()
                    && s.blocked(slot)
                    && s.ready_at(now, p.bytes.len() + 28) <= now
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_sockets_with_expired_work_poll_for_credit_then_writability() {
        let mut s = Scheduler::new(10_000_000, 1500, 2, 1).unwrap();
        s.block(0, 0);
        s.block(1, 0);
        // A prior payment on this shared direction drained the burst.
        s.paid(Class::Data, 0, 1500, 0);
        for (now, expected) in [(0, Some(92)), (92, Some(1212)), (1212, None)] {
            let due = s
                .after_idle_scan(now, Some(0), [100, 1500].into_iter(), || {
                    panic!("all paths blocked")
                })
                .unwrap();
            assert_eq!(due, expected);
            assert_eq!(s.ready_at(now, 100) <= now, now >= 92);
            assert_eq!(s.ready_at(now, 1500) <= now, now >= 1212);
        }
        s.writable(1);
        assert!(s.blocked(0) && !s.blocked(1));
        // The idle healthy path has a future protocol timer behind the stale minimum.
        assert_eq!(
            s.after_idle_scan(1212, Some(0), [100].into_iter(), || Ok(Some(1300)))
                .unwrap(),
            Some(1300)
        );
        assert_eq!(
            s.after_idle_scan(1212, Some(1400), [100].into_iter(), || panic!(
                "future deadline is already actionable"
            ))
            .unwrap(),
            Some(1400)
        );
        // With no socket blocked, overdue protocol work remains immediately runnable.
        assert_eq!(
            s.after_idle_scan(1212, Some(0), std::iter::empty(), || panic!(
                "no blocked paths"
            ))
            .unwrap(),
            Some(0)
        );
    }

    #[test]
    fn shared_serialization_reserves_the_next_packet_without_charging_blocked_sends() {
        let mut s = Scheduler::new(10_000_000, 1500, 6, 1).unwrap();
        s.paid(Class::Ack, 0, 1500, 0);
        assert_eq!(s.ready_at(0, 100), 92);
        assert_eq!(s.ready_at(0, 1500), 1212);
        s.reserve(Class::Data, 4, 1, s.ready_at(1, 1500));
        assert_eq!(s.waiting(), Some((Class::Data, 4)));
        s.block(4, 1212);
        assert!(s.waiting().is_none() && s.blocked(4));
        assert_eq!(s.stats.paid_packets, 1);
        assert_eq!(s.ready_at(1212, 1500), 1212);
        s.paid(Class::Data, 5, 1500, 1212);
        assert_eq!(s.stats.paid_ethernet_bytes, 3028);
        assert_eq!(s.ready_at(10_000, 1500), 10_000);
        s.paid(Class::Data, 3, 1500, 10_000);
        assert_eq!(s.ready_at(10_000, 1500), 11_212);
    }

    #[test]
    fn a_funded_head_stays_payable_during_ingress_without_borrowing_future_credit() {
        let mut s = Scheduler::new(100_000_000, 1500, 12, 1).unwrap();
        s.paid(Class::Data, 0, 1500, 0);
        let ready = s.ready_at(10, 1500);
        assert_eq!(ready, 122);
        s.reserve(Class::Request, 7, 10, ready);
        assert_eq!(s.waiting.filter(|r| r.ready <= 121).map(|r| r.slot), None);
        s.poll_timeout(50, 90);
        assert_eq!(s.stats.reserved_poll_timeouts, 0);
        s.poll_timeout(90, 149);
        assert_eq!(s.stats.reserved_poll_timeout_late_us, 27);
        assert_eq!(
            s.waiting.filter(|r| r.ready <= 149).map(|r| r.slot),
            Some(7)
        );
        assert_eq!(s.stats.paid_packets, 1);
        s.paid(Class::Request, 7, 1500, 150);
        assert_eq!(s.waiting.filter(|r| r.ready <= 150).map(|r| r.slot), None);
        assert_eq!(s.stats.reserved_payment_late_us, 28);
        assert_eq!(s.stats.paid_ethernet_bytes, 3028);
        assert_eq!(s.ready_at(150, 1500), 272);
        assert_eq!(s.classes()[0], Class::Data);
    }

    #[test]
    fn two_frames_retain_earned_late_wake_credit_but_never_grant_a_second_startup_frame() {
        // A 197 us service interval at 100 Mbit/s earns 2462.5 bytes.
        for (frames, next) in [(1, 10_319), (2, 10_243)] {
            let mut s = Scheduler::new(100_000_000, 1500, 12, frames).unwrap();
            assert_eq!(s.burst_bytes(), 1514 * u64::from(frames));
            assert_eq!(s.available(10_000), 1514 * UNITS_PER_BYTE);
            s.paid(Class::Data, 0, 1500, 10_000);
            assert_eq!(s.ready_at(10_000, 1500), 10_122);
            s.reserve(Class::Data, 1, 10_001, 10_122);
            let before_block = s.available(10_197);
            s.block(1, 10_197);
            assert_eq!(s.available(10_197), before_block);
            assert_eq!(s.stats.paid_packets, 1);
            s.writable(1);
            s.paid(Class::Data, 1, 1500, 10_197);
            assert_eq!(s.ready_at(10_197, 1500), next);
            assert_eq!(s.ready_at(next - 1, 1500), next);
            s.paid(Class::Data, 2, 1500, next);
            assert_eq!(s.stats.paid_ethernet_bytes, 4542);
            assert_eq!(
                s.available(100_000),
                u128::from(s.burst_bytes()) * UNITS_PER_BYTE
            );
        }
        for invalid in [0, 9, u8::MAX] {
            assert!(Scheduler::new(100_000_000, 1500, 12, invalid).is_err());
        }
    }

    #[test]
    fn every_mixed_size_interval_obeys_one_shared_frame_of_burst() {
        let rate = 10_000_000;
        let mut s = Scheduler::new(rate, 1500, 6, 1).unwrap();
        let mut paid = Vec::new();
        let mut now = 0;
        for (i, size) in [85, 1500, 70, 750, 1200, 300, 70, 95, 1500]
            .into_iter()
            .cycle()
            .take(100)
            .enumerate()
        {
            let at = s.ready_at(now, size);
            if at > now {
                assert!(s.ready_at(at - 1, size) > at - 1);
            }
            let class = s.classes()[0];
            s.paid(class, i as u8 % 6, size, at);
            paid.push((at, size as u64 + ETHERNET_HEADER));
            now = at + (if i % 23 == 0 { 3000 } else { 1 });
        }
        for i in 0..paid.len() {
            let mut bytes = 0;
            for &(t, len) in &paid[i..] {
                bytes += len;
                assert!(bytes * 8_000_000 <= 1514 * 8_000_000 + (t - paid[i].0) * rate);
            }
        }
    }

    #[test]
    fn all_busy_classes_and_each_of_their_paths_rotate() {
        let mut s = Scheduler::new(100_000_000, 1500, 6, 1).unwrap();
        for slot in 0..6 {
            for class in [Class::Ack, Class::Request, Class::Data] {
                assert!(s.classes()[0] == class);
                assert_eq!(s.path(class, 0), slot);
                s.paid(
                    class,
                    slot,
                    60,
                    1_000 * u64::from(slot) + 100 * class.index() as u64,
                );
            }
        }
    }
}

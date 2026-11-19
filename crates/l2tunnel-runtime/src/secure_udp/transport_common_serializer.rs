//! Whole ordinary IP packets on the sender-local virtual serializer.
use super::*;
use std::collections::VecDeque;

const MIN_IP_BYTES: usize = 20;

#[derive(Clone, Copy)]
struct Packet {
    end: u128,
    size: usize,
}

pub(in super::super) struct SerializerPlan {
    limit: usize,
    slots: usize,
}
impl SerializerPlan {
    pub(in super::super) fn new(mtu: usize) -> io::Result<Self> {
        let limit = mtu.checked_mul(8).ok_or_else(exhausted)?;
        let slots = limit / MIN_IP_BYTES + 1;
        Ok(Self { limit, slots })
    }

    pub(in super::super) fn heap_bytes(&self) -> io::Result<usize> {
        self.slots
            .checked_mul(size_of::<Packet>())
            .ok_or_else(exhausted)
    }

    pub(in super::super) fn build(self) -> io::Result<SerializerEstimate> {
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(self.slots)
            .map_err(io::Error::other)?;
        if pending.capacity() != self.slots {
            return Err(protocol("near8 serializer reservation differs from plan"));
        }
        Ok(SerializerEstimate {
            pending,
            limit: self.limit,
            bytes: 0,
            cursor: 0,
            end: 0,
            at: 0,
            rate: 0,
        })
    }
}

pub(in super::super) struct SerializerEstimate {
    pending: VecDeque<Packet>,
    limit: usize,
    bytes: usize,
    cursor: u128,
    end: u128,
    at: u64,
    rate: u64,
}
impl SerializerEstimate {
    /// Both ordinary and near packets occupy the wire. Only whole ordinary
    /// packets still awaiting their last byte contribute to the near8 gate.
    pub(in super::super) fn observe(&mut self, now: u64, rate: u64) -> io::Result<usize> {
        let elapsed = now
            .checked_sub(self.at)
            .ok_or_else(|| protocol("serializer clock regression"))?;
        self.cursor = self.end.min(
            self.cursor
                .saturating_add(u128::from(elapsed) * u128::from(self.rate)),
        );
        self.at = now;
        self.rate = rate;
        while self.pending.front().is_some_and(|p| p.end <= self.cursor) {
            self.drop_front()?;
        }
        if self.cursor == self.end {
            self.cursor = 0;
            self.end = 0;
        }
        Ok(self.bytes)
    }

    pub(in super::super) fn accepted(
        &mut self,
        now: u64,
        rate: u64,
        size: usize,
        near: bool,
    ) -> io::Result<()> {
        self.observe(now, rate)?;
        if size < MIN_IP_BYTES || rate == 0 {
            return Err(protocol("invalid near8 IP serializer receipt"));
        }
        self.end = self
            .end
            .checked_add(size as u128 * SCALE)
            .ok_or_else(exhausted)?;
        if !near {
            // Discard older deadlines only if the retained newer suffix alone
            // exceeds the maximum negotiated threshold. Before any newer
            // packet departs, all omitted packets have already departed.
            while self
                .pending
                .front()
                .is_some_and(|p| (self.bytes - p.size).saturating_add(size) > self.limit)
            {
                self.drop_front()?;
            }
            if self.pending.len() == self.pending.capacity() {
                return Err(protocol("near8 IP serializer exceeded its slot proof"));
            }
            self.pending.push_back(Packet {
                end: self.end,
                size,
            });
            self.bytes += size;
        }
        Ok(())
    }

    fn drop_front(&mut self) -> io::Result<()> {
        let packet = self
            .pending
            .pop_front()
            .ok_or_else(|| protocol("missing serializer packet"))?;
        self.bytes -= packet.size;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_delays_ordinary_without_adding_ordinary_bytes() -> io::Result<()> {
        let mut s = SerializerPlan::new(1500)?.build()?;
        s.accepted(0, 1_000_000, 100, true)?;
        assert_eq!(s.observe(10, 1_000_000)?, 0);
        s.accepted(10, 1_000_000, 40, false)?;
        assert_eq!(s.observe(100, 1_000_000)?, 40);
        assert_eq!(s.observe(139, 1_000_000)?, 40);
        assert_eq!(s.observe(140, 1_000_000)?, 0);
        s.accepted(180, 1_000_000, 100, false)?;
        assert_eq!(s.observe(200, 2_000_000)?, 100);
        assert_eq!(s.observe(239, 2_000_000)?, 100);
        assert_eq!(s.observe(240, 2_000_000)?, 0);
        Ok(())
    }

    #[test]
    fn complete_packets_and_near_service_match_full_fifo() -> io::Result<()> {
        let mut s = SerializerPlan::new(1500)?.build()?;
        let mut full = VecDeque::new();
        let mut end = 0;
        let rate = 1_000_000;
        for i in 0..2400 {
            let at = i * 3;
            let size = 20 + (i % 19) as usize;
            let near = i % 5 == 0;
            end = at.max(end) + size as u64;
            if !near {
                full.push_back((end, size));
            }
            s.accepted(at, rate, size, near)?;
            let expected: usize = full.iter().filter(|(e, _)| *e > at).map(|(_, n)| n).sum();
            assert_eq!(s.observe(at, rate)?.min(12_001), expected.min(12_001));
        }
        for at in (7197..end + 2).step_by(37) {
            let expected: usize = full.iter().filter(|(e, _)| *e > at).map(|(_, n)| n).sum();
            assert_eq!(s.observe(at, rate)?.min(12_001), expected.min(12_001));
        }
        assert_eq!(s.observe(end + 2, rate)?, 0);
        Ok(())
    }
}

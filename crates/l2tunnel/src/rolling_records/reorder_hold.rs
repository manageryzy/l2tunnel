//! Opt-in bounded TCP byte-order hold after authenticated packet reconstruction.
//! The codec retains the original body and token. Only a physical native write
//! advances the flow edge. Timers use the caller's monotonic microsecond clock.
use super::*;
use crate::rolling_records::NativeReorderStatus;
use crate::rolling_records::receiver::EarlyDecision;

const HOLD_US: u64 = 35_000;
const MAX_SPAN: u32 = 256 * 1024;
const RANGE_LIMIT: usize = 32;

#[derive(Clone, Copy, Default)]
enum Phase {
    #[default]
    Open,
    Waiting {
        until: u64,
        through: u32,
    },
    Bypass {
        through: u32,
    },
    Untracked,
}

#[derive(Default)]
struct Slot {
    phase: Phase,
    // Materialized native writes only. Never infer delivery over a missing interval.
    delivered: arrayvec::ArrayVec<(u32, u32), RANGE_LIMIT>,
}

impl Slot {
    fn committed(
        &mut self,
        edge: &mut Edge,
        t: &Tcp,
        before: u32,
        status: &mut NativeReorderStatus,
    ) -> bool {
        if matches!(self.phase, Phase::Untracked) {
            return false;
        }
        if matches!(self.phase, Phase::Bypass { .. }) && t.payload != 0 && after(t.seq, before) {
            status.bypass_writes = status.bypass_writes.saturating_add(1);
        }
        if after(t.seq, edge.next) && after(t.end, t.seq) {
            let mut range = (t.seq, t.end);
            let pos = self.delivered.partition_point(|r| after(range.0, r.1));
            while pos < self.delivered.len() && !after(self.delivered[pos].0, range.1) {
                let other = self.delivered.remove(pos);
                if after(range.0, other.0) {
                    range.0 = other.0;
                }
                if after(other.1, range.1) {
                    range.1 = other.1;
                }
            }
            if self.delivered.try_insert(pos, range).is_err() {
                self.phase = Phase::Untracked;
                self.delivered.clear();
                status.range_overflows = status.range_overflows.saturating_add(1);
                return true;
            }
        }
        while self
            .delivered
            .first()
            .is_some_and(|r| !after(r.0, edge.next))
        {
            let (_, end) = self.delivered.remove(0);
            if after(end, edge.next) {
                edge.next = end;
            }
        }
        if let Phase::Waiting { through, .. } | Phase::Bypass { through } = self.phase
            && !after(through, edge.next)
        {
            let count = if matches!(self.phase, Phase::Waiting { .. }) {
                &mut status.prefix_closes
            } else {
                &mut status.bypass_prefix_closes
            };
            *count = count.saturating_add(1);
            self.phase = Phase::Open;
        }
        false
    }
}

#[derive(Default)]
pub(super) struct Holds {
    slots: Vec<[Slot; WAYS]>,
    earliest: Option<u64>,
    status: NativeReorderStatus,
}

impl Holds {
    fn slot_count<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        if direction.native_policy.is_ip() && direction.scheduler.hold_native_reordering() {
            Guard::slots(direction)
        } else {
            0
        }
    }
    pub(super) fn planned_bytes<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> usize {
        Self::slot_count(direction) * size_of::<[Slot; WAYS]>()
    }
    pub(super) fn capacity_bytes(&self) -> usize {
        self.slots.capacity() * size_of::<[Slot; WAYS]>()
    }
    pub(super) fn new<P: RecoveryPolicy>(direction: DirectionConfig<P>) -> Result<Self, Error> {
        let count = Self::slot_count(direction);
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| Error::Allocation)?;
        slots.resize_with(count, Default::default);
        Ok(Self {
            slots,
            earliest: None,
            status: Default::default(),
        })
    }
    pub(super) fn reset(&mut self, bucket: usize, i: usize) {
        if let Some(group) = self.slots.get_mut(bucket) {
            group[i] = Slot::default();
        }
    }
    pub(super) fn committed(
        &mut self,
        bucket: usize,
        i: usize,
        edge: &mut Edge,
        tcp: &Tcp,
        before: u32,
    ) -> bool {
        self.slots
            .get_mut(bucket)
            .is_some_and(|group| group[i].committed(edge, tcp, before, &mut self.status))
    }
}

impl Guard {
    pub(in crate::rolling_records) fn hold_status(&self) -> Option<NativeReorderStatus> {
        self.holds_enabled().then_some(self.holds.status)
    }
    pub(in crate::rolling_records) fn holds_enabled(&self) -> bool {
        !self.holds.slots.is_empty()
    }
    pub(in crate::rolling_records) fn hold_wake(&self) -> Option<u64> {
        self.holds.earliest
    }
    /// A soft release invalidates cached per-record dependency tokens even
    /// when no carrier input or new contiguous TCP byte arrived.
    pub(in crate::rolling_records) fn expire_holds(&mut self, now: u64) -> bool {
        if self.holds.earliest.is_none_or(|time| now < time) {
            return false;
        }
        self.holds.earliest = None;
        let mut changed = false;
        for (bucket, group) in self.edges.iter_mut().zip(&mut self.holds.slots) {
            for (slot, hold) in bucket.slots.iter_mut().zip(group) {
                if let Phase::Waiting { until, through } = hold.phase {
                    if now >= until {
                        hold.phase = Phase::Bypass { through };
                        self.holds.status.deadline_releases =
                            self.holds.status.deadline_releases.saturating_add(1);
                        bump(&mut slot.version);
                        changed = true;
                    } else {
                        self.holds.earliest =
                            Some(self.holds.earliest.map_or(until, |v| v.min(until)));
                    }
                }
            }
        }
        changed
    }

    pub(in crate::rolling_records) fn held_ip_decision(
        &mut self,
        policy: NativePolicy,
        bytes: &[u8],
        now: u64,
        short: bool,
        early: bool,
    ) -> EarlyDecision {
        let packet = packet(policy, bytes);
        if early {
            let usual = self.decide_packet(&packet, now, super::Release::Independent, short);
            if !matches!(usual, EarlyDecision::Allow) {
                return usual;
            }
        }
        let Packet::Tcp(t) = &packet else {
            return EarlyDecision::Allow;
        };
        if t.payload == 0 || t.flags & (SYN | FIN | RST) != 0 || t.flags & ACK == 0 {
            return EarlyDecision::Allow;
        }
        let bucket = self.bucket(t);
        let Some((i, slot)) = self.edges[bucket]
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.edge.is_some_and(|edge| edge.key == t.source))
        else {
            return EarlyDecision::Allow;
        };
        let Some(edge) = slot.edge else {
            return EarlyDecision::Allow;
        };
        if !edge.proven
            || now.saturating_sub(edge.last) >= self.lifetime
            || !after(t.seq, edge.next)
            || !after(t.end, edge.next)
            || slot.version >= VERSION_MAX
        {
            return EarlyDecision::Allow;
        }
        let phase = &mut self.holds.slots[bucket][i].phase;
        if matches!(phase, Phase::Bypass { .. } | Phase::Untracked) {
            return EarlyDecision::Allow;
        }
        let through = match *phase {
            Phase::Waiting { through, .. } if after(through, t.end) => through,
            _ => t.end,
        };
        if through.wrapping_sub(edge.next) > MAX_SPAN {
            *phase = Phase::Bypass { through };
            self.holds.status.span_releases = self.holds.status.span_releases.saturating_add(1);
            bump(&mut slot.version);
            return EarlyDecision::Allow;
        }
        let until = match *phase {
            Phase::Waiting { until, .. } => until,
            _ => {
                let Some(until) = now.checked_add(HOLD_US) else {
                    return EarlyDecision::Allow;
                };
                self.holds.status.starts = self.holds.status.starts.saturating_add(1);
                self.holds.earliest = Some(self.holds.earliest.map_or(until, |v| v.min(until)));
                until
            }
        };
        *phase = Phase::Waiting { until, through };
        let version = slot.version;
        self.wait(bucket * (WAYS + 1) + i, version)
    }
}

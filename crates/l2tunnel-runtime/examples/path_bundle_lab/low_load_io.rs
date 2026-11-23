//! Optional startup copies use idle service and the ordinary immutable DATA owner.
use super::*;

impl Driver {
    pub(super) fn send_low_load(&mut self, now: u64) -> Result<bool> {
        self.low_load_wake = None;
        if !self
            .low_load
            .as_ref()
            .is_some_and(low_load::Policy::has_candidate)
            || !self.path_ready()
            || !self.credit()
            || !self.requests.is_empty()
            || self.wire.iter().any(Option::is_some)
            || self.native.next(self.rx.confirmed_prefix()).is_some()
            || self.pacing.as_ref().is_none_or(|s| s.waiting().is_some())
        {
            return Ok(false);
        }
        // Even a partial ordinary batch takes precedence over speculative work.
        for slot in 0..self.cfg.n {
            if self.recovery.has_queued_repair(slot)
                || self.tx.next_wake(PathId::new(slot)?)?.is_some()
            {
                return Ok(false);
            }
        }
        let Some(member) = self
            .low_load
            .as_mut()
            .ok_or("missing low-load policy")?
            .candidate(now, |g, o| {
                self.recovery.retains(g)
                    && !self.tx.peer_has_rank(g)
                    && !self.tx.peer_has_member(g, o)
            })?
        else {
            return Ok(false);
        };
        let Some(slot) = (0..self.cfg.n)
            .map(|offset| rotate(member.ordinal, offset + 1, self.cfg.n))
            .find(|&slot| {
                !self.pacing.as_ref().is_some_and(|s| s.blocked(slot))
                    && self.physical[usize::from(slot)].can_send()
            })
        else {
            return Ok(false);
        };
        let ready = self
            .pacing
            .as_ref()
            .ok_or("missing pacing")?
            .ready_at(now, self.path.mtu);
        if ready > now {
            // This is a wake hint, not a reservation: any normal work arriving
            // before the next turn gets first use of the accumulated credit.
            self.low_load_wake = Some(ready);
            return Ok(false);
        }
        let path = PathId::new(slot)?;
        if !self
            .tx
            .request(path, us(now), member.group, member.ordinal)?
        {
            self.low_load
                .as_mut()
                .ok_or("missing low-load policy")?
                .release(member.group);
            return Ok(false);
        }
        let prepared = self
            .tx
            .prepare(path, us(now), None)?
            .ok_or("missing immediate copy")?;
        let token = prepared.id;
        let due = prepared.deadline.as_micros() as u64;
        let mut charges = self
            .recovery
            .charges(path, self.path.decode(path, prepared.bytes)?)?;
        if charges.len() != 1
            || charges[0].id != member.group
            || charges[0].ordinal != member.ordinal
        {
            return Err("idle copy shared an ordinary batch".into());
        }
        charges[0].role = Role::LowLoad;
        charges[0].price = Role::LowLoad;
        let mut bytes = vec![0; 1 + self.send.overhead() + prepared.bytes.len()];
        bytes[0] = ROUTE;
        let sealed = self.send.seal(
            metadata(self.digest, &[ROUTE, slot]),
            prepared.bytes,
            &mut bytes[1..],
        )?;
        self.low_load
            .as_mut()
            .ok_or("missing low-load policy")?
            .freeze(member, now)?;
        self.wire[usize::from(slot)] = Some(Pending {
            pn: sealed.number.0,
            bytes,
            kind: Kind::Data(token, charges),
            receipt: None,
            due,
        });
        // WouldBlock retains this exact authenticated head and normal physical
        // sequence. Only successful handoff updates the copy and recovery clocks.
        self.send_pending(slot)
    }
}

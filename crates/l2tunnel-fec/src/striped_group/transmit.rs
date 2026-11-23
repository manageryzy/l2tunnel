use super::{GroupHeader, GroupShape, Profile, Sender, TransmitPlan, transmit_storage::Groups};
use crate::{Error, FecContext, GenerationId, storage};

/// One original physical transmission. Retain this token and its ciphertext
/// until the carrier accepts the complete datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshMember {
    context: FecContext,
    generation: GenerationId,
    ordinal: u8,
}

impl FreshMember {
    /// First logical source in this sealed group.
    pub const fn generation(self) -> GenerationId {
        self.generation
    }

    /// Physical ordinal, including the second member of a split singleton.
    pub const fn ordinal(self) -> u8 {
        self.ordinal
    }
}

impl GroupHeader {
    fn logical_count(&self) -> u16 {
        match self.shape {
            GroupShape::Originals(q) => q,
            GroupShape::Split(_) => 1,
        }
    }

    pub(super) fn last_source(&self) -> GenerationId {
        // Sender assigns each original a checked contiguous ID before sealing.
        GenerationId(self.generation.0 + u64::from(self.logical_count() - 1))
    }
}

/// Bounded custody for a single negotiated direction and epoch. The window
/// counts staged originals and all originals in retained sealed groups. Across
/// those groups each source can own at most two expanded member bodies.
/// Peer feedback must already be authenticated before entering this API.
pub struct TransmitWindow {
    context: FecContext,
    sender: Sender,
    groups: Groups,
    pub(super) limit: usize,
    retained: usize,
    fresh: usize,
    ordinal: u16,
    provable: Option<GenerationId>,
    confirmed: Option<GenerationId>,
    first: GenerationId,
}

impl TransmitWindow {
    /// Start at an unassigned logical source ID. Positive credit below the
    /// nominal group size is valid and produces deadline-shortened groups.
    pub fn new(
        profile: Profile,
        context: FecContext,
        first: GenerationId,
        hold: u64,
        now: u64,
        source_limit: usize,
    ) -> Result<Self, Error> {
        if source_limit == 0 {
            return Err(Error::InvalidConfig);
        }
        Ok(Self {
            context,
            sender: Sender::new(profile, hold, first, now)?,
            groups: Groups::Growing(Default::default()),
            limit: source_limit,
            retained: 0,
            fresh: 0,
            ordinal: 0,
            provable: None,
            confirmed: None,
            first,
        })
    }

    /// Build the same physical send, confirmation and named-retry state machine
    /// with all member custody preallocated under the supplied heap limit.
    pub fn new_reserved(
        plan: TransmitPlan,
        limits: storage::Limits,
        context: FecContext,
        first: GenerationId,
        hold: u64,
        now: u64,
    ) -> Result<Self, storage::Error> {
        if plan.capacity_bytes() > limits.capacity_bytes {
            return Err(storage::Error::Limit {
                required: plan.capacity_bytes(),
                limit: limits.capacity_bytes,
            });
        }
        let mut window = Self::new(plan.profile, context, first, hold, now, plan.sources)
            .map_err(storage::Error::Fec)?;
        window.groups =
            Groups::reserved(plan, limits.capacity_bytes, window.sender.staged.capacity())?;
        Ok(window)
    }

    /// Actual retained backing for the fixed-layout constructor.
    pub fn storage_usage(&self) -> Option<storage::Usage> {
        match &self.groups {
            Groups::Growing(_) => None,
            Groups::Reserved { usage, .. } => Some(*usage),
        }
    }

    /// Logical source slots still retained, including a partly confirmed group.
    pub const fn retained(&self) -> usize {
        self.retained
    }

    /// Completed group shapes and their original batch timing.
    pub const fn group_formation(&self) -> super::GroupFormation {
        self.sender.formation
    }

    /// Assigned logical sources beyond the authenticated cumulative prefix,
    /// including staged originals. A held, partially confirmed group can use
    /// more physical custody slots than this number.
    pub fn outstanding_sources(&self) -> usize {
        let end = self.sender.next.map_or(1_u128 << 64, |id| u128::from(id.0));
        let start = self
            .confirmed
            .map_or(u128::from(self.first.0), |id| u128::from(id.0) + 1);
        // Assigned, unconfirmed sources are bounded by the retained aperture.
        (end - start) as usize
    }

    /// Earliest local send or seal work. A deadline in the past is immediately
    /// actionable. A caller retaining ciphertext across WouldBlock waits for
    /// carrier capacity before retrying that same output.
    pub fn next_wake(&self) -> Option<u64> {
        if self.fresh < self.groups.len() {
            Some(self.sender.last_tick)
        } else {
            self.sender.next_wake()
        }
    }

    /// Stage a source without consuming its ID or evicting an old hole on refusal.
    pub fn submit(&mut self, now: u64, original: &[u8]) -> Result<GenerationId, Error> {
        if self.retained == self.limit {
            return Err(Error::Capacity);
        }
        let id = self.sender.submit(now, original)?;
        self.retained += 1;
        Ok(id)
    }

    /// Encode the next fresh physical member. Preparing an output twice is
    /// idempotent. Other groups can be sealed while earlier members are pending.
    pub fn prepare_fresh(
        &mut self,
        now: u64,
        output: &mut [u8],
    ) -> Result<Option<(FreshMember, usize)>, Error> {
        let profile = self.sender.profile;
        self.sender.poll_with(now, |header, originals| {
            self.groups.seal(profile, header, originals)
        })?;
        let Some(group) = self.groups.header(self.fresh) else {
            return Ok(None);
        };
        let token = FreshMember {
            context: self.context,
            generation: group.generation,
            ordinal: self.ordinal as u8,
        };
        let used = self.groups.write(self.fresh, token.ordinal, output)?;
        Ok(Some((token, used)))
    }

    /// Formation of the actual first fresh member, including while a later group
    /// has sealed but this member is still under carrier backpressure.
    pub(super) fn first_member_seal(&self, member: FreshMember) -> Option<super::GroupSeal> {
        if member.context != self.context || member.ordinal != 0 || self.ordinal != 0 {
            return None;
        }
        let group = self.groups.header(self.fresh)?;
        (member.generation == group.generation).then_some(group.seal)
    }

    /// Confirm complete physical acceptance. At the kth distinct original
    /// transmission the peer can legitimately acknowledge the entire group,
    /// even while further fresh members await carrier admission.
    pub fn confirm_fresh(&mut self, member: FreshMember) -> Result<(), Error> {
        if member.context != self.context {
            return Err(Error::ContextMismatch);
        }
        let group = self.groups.header(self.fresh).ok_or(Error::Unsealed)?;
        if member.generation != group.generation || u16::from(member.ordinal) != self.ordinal {
            return Err(Error::Conflict);
        }
        self.ordinal += 1;
        self.provable = Some(if self.ordinal >= group.geometry.data_cells() {
            group.last_source()
        } else {
            GenerationId(member.generation.0 + u64::from(member.ordinal))
        });
        if usize::from(self.ordinal) == group.geometry.packet_count() {
            self.fresh += 1;
            self.ordinal = 0;
            self.release_confirmed();
        }
        Ok(())
    }

    /// Encode the immutable mixed member for an authenticated named retry.
    /// A split singleton uses its first member, which contains both halves.
    /// An authenticated request can name a sealed member before its first
    /// physical acceptance. Unsealed leaves it scheduled as a fresh output.
    /// The outer session assigns a new security packet number to a retry.
    pub fn write_named(
        &self,
        context: FecContext,
        source: GenerationId,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if context != self.context {
            return Err(Error::ContextMismatch);
        }
        if source < self.first || self.confirmed.is_some_and(|id| source <= id) {
            return Err(Error::StaleGeneration);
        }
        let position = self.groups.find(source);
        let group = self
            .groups
            .header(position)
            .ok_or(Error::UnknownGeneration)?;
        let index = source
            .0
            .checked_sub(group.generation.0)
            .ok_or(Error::UnknownGeneration)?;
        if position > self.fresh || (position == self.fresh && index >= u64::from(self.ordinal)) {
            return Err(Error::Unsealed);
        }
        self.groups.write(
            position,
            u8::try_from(index).map_err(|_| Error::UnknownGeneration)?,
            output,
        )
    }

    /// Accept a cumulative inclusive source acknowledgment. Reordered or
    /// repeated confirmations cannot resurrect credit or discard a live gap.
    pub fn confirm_through(
        &mut self,
        context: FecContext,
        last: GenerationId,
    ) -> Result<bool, Error> {
        if context != self.context {
            return Err(Error::ContextMismatch);
        }
        if last < self.first || self.confirmed.is_some_and(|id| last <= id) {
            return Ok(false);
        }
        if self.provable.is_none_or(|id| last > id) {
            return Err(Error::UnknownGeneration);
        }
        self.confirmed = Some(last);
        self.release_confirmed();
        Ok(true)
    }

    fn release_confirmed(&mut self) {
        let Some(last) = self.confirmed else {
            return;
        };
        while self.fresh > 0
            && let Some(group) = self.groups.header(0)
        {
            if group.last_source() > last {
                break;
            }
            self.retained -= usize::from(group.logical_count());
            self.fresh -= 1;
            self.groups.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChannelId, Direction, Epoch, SessionId};

    const PROFILE: Profile = Profile {
        data_cells: 2,
        parity_cells: 1,
        max_body_bytes: 1400,
        max_wire_bytes: 1400,
    };
    const CONTEXT: FecContext = FecContext {
        session: SessionId([8; 16]),
        direction: Direction::ClientToServer,
        epoch: Epoch(17),
        channel: ChannelId(1),
    };

    #[test]
    fn first_member_seal_matches_actual_batch_under_backpressure()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = Profile {
            data_cells: 10,
            parity_cells: 2,
            max_body_bytes: 1451,
            max_wire_bytes: 1451,
        };
        let plan = TransmitPlan::for_window(profile, 3)?;
        let limits = storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        let mut tx =
            TransmitWindow::new_reserved(plan, limits, CONTEXT, GenerationId(40), 1500, 0)?;
        for (time, n) in [(20, 1079), (43, 1079), (43, 820)] {
            tx.submit(time, &vec![0x55; n])?;
        }
        let mut buf = [0; 1451];
        assert!(tx.prepare_fresh(1519, &mut buf)?.is_none());
        // Sealing succeeds before the output buffer can take the first member.
        assert!(matches!(
            tx.prepare_fresh(1520, &mut []),
            Err(Error::OutputTooSmall { .. })
        ));
        let (first, len) = tx.prepare_fresh(1528, &mut buf)?.ok_or(Error::Unsealed)?;
        let mut same = [0; 1451];
        assert_eq!(tx.prepare_fresh(1551, &mut same)?, Some((first, len)));
        assert_eq!(buf[..len], same[..len]);
        // Groups 41 and 42 sealed behind group 40 at 1528 and 1551 respectively.
        // Their eventual first selection must report those earlier ticks.
        for (generation, at, remaining, longest) in
            [(40, 1520, 3, 1079), (41, 1528, 2, 1079), (42, 1551, 1, 820)]
        {
            let (token, _) = tx.prepare_fresh(1640, &mut buf)?.ok_or(Error::Unsealed)?;
            assert_eq!((token.generation().0, token.ordinal()), (generation, 0));
            assert_eq!(
                tx.first_member_seal(token),
                Some(super::super::GroupSeal {
                    at,
                    deadline: 1520,
                    batch_offset: (generation - 40) as u16,
                    remaining,
                    longest,
                    selected: 1,
                })
            );
            tx.confirm_fresh(token)?;
            assert_eq!(tx.first_member_seal(token), None);
            let (second, _) = tx.prepare_fresh(1640, &mut buf)?.ok_or(Error::Unsealed)?;
            assert_eq!((second.generation().0, second.ordinal()), (generation, 1));
            assert_eq!(tx.first_member_seal(second), None);
            tx.confirm_fresh(second)?;
        }
        assert_eq!(tx.group_formation().mtu_splits, 2);
        assert_eq!(tx.group_formation().trailing_splits, 1);
        assert_eq!(
            tx.storage_usage()
                .ok_or(Error::InvalidConfig)?
                .capacity_bytes,
            plan.capacity_bytes()
        );
        Ok(())
    }

    #[test]
    fn backpressure_keeps_members_and_credit_until_provable_ack_and_physical_send()
    -> Result<(), Error> {
        let base = GenerationId(u64::MAX - 2);
        let mut tx = TransmitWindow::new(PROFILE, CONTEXT, base, 4, 0, 3)?;
        for byte in [7, 8, 9] {
            tx.submit(0, &[byte; 32])?;
        }
        assert_eq!(tx.submit(0, b"next"), Err(Error::Capacity));
        let mut a = [0; 128];
        let mut b = [0; 128];
        assert!(matches!(
            tx.prepare_fresh(0, &mut []),
            Err(Error::OutputTooSmall { .. })
        ));
        let (first, n) = tx.prepare_fresh(0, &mut a)?.ok_or(Error::Unsealed)?;
        assert_eq!(
            tx.first_member_seal(first),
            Some(super::super::GroupSeal {
                at: 0,
                deadline: 4,
                batch_offset: 0,
                remaining: 3,
                longest: 32,
                selected: 3,
            })
        );
        assert_eq!(tx.prepare_fresh(1, &mut b)?, Some((first, n)));
        assert_eq!(tx.next_wake(), Some(1));
        assert_eq!(a[..n], b[..n]);
        assert_eq!(
            tx.confirm_through(CONTEXT, base),
            Err(Error::UnknownGeneration)
        );
        assert_eq!(tx.write_named(CONTEXT, base, &mut b), Err(Error::Unsealed));
        tx.confirm_fresh(first)?;
        assert_eq!(tx.write_named(CONTEXT, base, &mut b)?, n);
        assert_eq!(a[..n], b[..n]);
        assert_eq!(tx.confirm_fresh(first), Err(Error::Conflict));
        assert_eq!(
            tx.confirm_through(CONTEXT, GenerationId(u64::MAX)),
            Err(Error::UnknownGeneration)
        );
        assert!(tx.confirm_through(CONTEXT, base)?);
        assert_eq!((tx.retained(), tx.outstanding_sources()), (3, 2));
        assert_eq!(
            tx.write_named(CONTEXT, base, &mut b),
            Err(Error::StaleGeneration)
        );
        let (second, _) = tx.prepare_fresh(2, &mut b)?.ok_or(Error::Unsealed)?;
        tx.confirm_fresh(second)?;
        let other = FecContext {
            epoch: Epoch(18),
            ..CONTEXT
        };
        assert_eq!(
            tx.confirm_through(other, GenerationId(u64::MAX)),
            Err(Error::ContextMismatch)
        );
        assert!(tx.confirm_through(CONTEXT, GenerationId(u64::MAX))?);
        assert_eq!(tx.outstanding_sources(), 0);
        assert!(!tx.confirm_through(CONTEXT, base)?);
        assert_eq!(tx.retained(), 3);
        let (last, _) = tx.prepare_fresh(2, &mut b)?.ok_or(Error::Unsealed)?;
        assert_eq!(last.ordinal(), 2);
        tx.confirm_fresh(last)?;
        assert_eq!(tx.retained(), 0);
        assert_eq!(tx.next_wake(), None);
        assert_eq!(tx.submit(3, b"next"), Err(Error::SymbolExhausted));
        Ok(())
    }

    #[test]
    fn named_old_source_survives_newer_groups_and_short_split_receipts() -> Result<(), Error> {
        let mut tx = TransmitWindow::new(PROFILE, CONTEXT, GenerationId(0), 2, 0, 4)?;
        let mut buf = [0; 128];
        for payload in [b"a", b"b", b"c"] {
            tx.submit(0, payload)?;
        }
        let (first, n) = tx.prepare_fresh(0, &mut buf)?.ok_or(Error::Unsealed)?;
        let expect = buf[..n].to_vec();
        tx.confirm_fresh(first)?;
        tx.submit(1, b"split alone")?;
        for ordinal in 1..3 {
            let (member, _) = tx.prepare_fresh(3, &mut buf)?.ok_or(Error::Unsealed)?;
            assert_eq!(member.ordinal(), ordinal);
            tx.confirm_fresh(member)?;
        }
        let (left, _) = tx.prepare_fresh(3, &mut buf)?.ok_or(Error::Unsealed)?;
        assert_eq!(left.generation(), GenerationId(3));
        tx.confirm_fresh(left)?;
        assert_eq!(tx.write_named(CONTEXT, GenerationId(0), &mut buf)?, n);
        assert_eq!(buf[..n], expect);
        assert!(tx.confirm_through(CONTEXT, GenerationId(3))?);
        assert_eq!(tx.retained(), 1);
        let (right, _) = tx.prepare_fresh(3, &mut buf)?.ok_or(Error::Unsealed)?;
        assert_eq!(right.ordinal(), 1);
        tx.confirm_fresh(right)?;
        assert_eq!(tx.retained(), 0);
        assert!(tx.prepare_fresh(4, &mut buf)?.is_none());
        Ok(())
    }

    #[test]
    fn reserved_custody_prices_actual_buffers_and_reuses_them_after_wrap()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = TransmitPlan::for_window(PROFILE, 5)?;
        let limits = storage::Limits {
            capacity_bytes: plan.capacity_bytes(),
        };
        assert!(matches!(
            TransmitPlan::for_window(PROFILE, usize::MAX),
            Err(storage::Error::Layout)
        ));
        assert!(
            matches!(TransmitWindow::new_reserved(plan, storage::Limits {
            capacity_bytes: limits.capacity_bytes-1 }, CONTEXT, GenerationId(123), 2, 0),
            Err(storage::Error::Limit {required, ..}) if required == limits.capacity_bytes)
        );
        let mut fixed =
            TransmitWindow::new_reserved(plan, limits, CONTEXT, GenerationId(123), 2, 0)?;
        let mut growing = TransmitWindow::new(PROFILE, CONTEXT, GenerationId(123), 2, 0, 5)?;
        let backing = |w: &TransmitWindow| {
            let Groups::Reserved {
                headers,
                arena,
                scratch,
                ..
            } = &w.groups
            else {
                return None;
            };
            Some((
                w.sender.staged.as_ptr(),
                arena.as_ptr(),
                scratch.as_ptr(),
                headers.capacity(),
                w.sender.staged.capacity()
                    + arena.capacity()
                    + scratch.capacity()
                    + headers.capacity() * size_of::<GroupHeader>(),
            ))
        };
        let backing_before = backing(&fixed).ok_or(Error::InvalidConfig)?;
        assert_eq!(backing_before.4, plan.capacity_bytes());
        let send = |a: &mut TransmitWindow,
                    b: &mut TransmitWindow,
                    now: u64|
         -> Result<FreshMember, Error> {
            let mut left = [0; 1400];
            let mut right = [0; 1400];
            let (before, n) = a.prepare_fresh(now, &mut left)?.ok_or(Error::Unsealed)?;
            assert_eq!(b.prepare_fresh(now, &mut right)?, Some((before, n)));
            assert_eq!(left[..n], right[..n]);
            assert_eq!(a.prepare_fresh(now, &mut right)?, Some((before, n)));
            assert_eq!(left[..n], right[..n]);
            a.confirm_fresh(before)?;
            b.confirm_fresh(before)?;
            Ok(before)
        };
        for round in 0u8..5 {
            let now = 10 * u64::from(round);
            let first = GenerationId(123 + 5 * u64::from(round));
            for i in 0u8..3 {
                let data = [i, round, 0xff];
                assert_eq!(fixed.submit(now, &data)?, growing.submit(now, &data)?);
            }
            for _ in 0..3 {
                send(&mut fixed, &mut growing, now)?;
            }
            for i in 3u8..5 {
                let data = [i; 127];
                assert_eq!(fixed.submit(now, &data)?, growing.submit(now, &data)?);
            }
            assert_eq!(fixed.submit(now, b"no space"), Err(Error::Capacity));
            for _ in 0..2 {
                send(&mut fixed, &mut growing, now + 2)?;
            }
            let mut a = [0; 1400];
            let mut b = [0; 1400];
            let n = fixed.write_named(CONTEXT, first, &mut a)?;
            assert_eq!(growing.write_named(CONTEXT, first, &mut b)?, n);
            assert_eq!(a[..n], b[..n]);
            for w in [&mut fixed, &mut growing] {
                w.confirm_through(CONTEXT, GenerationId(first.0 + 4))?;
                assert_eq!(w.retained(), 0);
            }
            assert_eq!(backing(&fixed), Some(backing_before));
        }
        // All five group headers can be live when every original times out alone.
        for i in 0u8..5 {
            let now = 60 + 4 * u64::from(i);
            for w in [&mut fixed, &mut growing] {
                w.submit(now, &[i])?;
            }
            for _ in 0..2 {
                send(&mut fixed, &mut growing, now + 2)?;
            }
        }
        assert_eq!(fixed.retained(), 5);
        assert_eq!(backing(&fixed), Some(backing_before));
        assert_eq!(
            fixed.storage_usage(),
            Some(storage::Usage {
                limit_bytes: plan.capacity_bytes(),
                capacity_bytes: plan.capacity_bytes(),
                allocations: 4
            })
        );
        Ok(())
    }

    #[test]
    fn reserved_custody_capacity_breakdown_matches_engine_fixtures_and_single_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        for (label, bound, slots) in [
            ("single_flow_mtu1500_minus_49", 1451, 8192),
            ("striped_native_fixture", 1400, 32),
            ("striped_engine_fixture", 1000, 20),
        ] {
            let profile = Profile {
                data_cells: 4,
                parity_cells: 1,
                max_body_bytes: bound,
                max_wire_bytes: bound,
            };
            let plan = TransmitPlan::for_window(profile, slots)?;
            let limits = storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            };
            let window =
                TransmitWindow::new_reserved(plan, limits, CONTEXT, GenerationId(0), 5, 0)?;
            let Groups::Reserved {
                headers,
                arena,
                scratch,
                usage,
                ..
            } = &window.groups
            else {
                return Err(Error::InvalidConfig.into());
            };
            let staging = window.sender.staged.capacity();
            let group_headers = headers.capacity() * size_of::<GroupHeader>();
            assert_eq!(
                plan.capacity_bytes(),
                staging + group_headers + arena.capacity() + scratch.capacity()
            );
            assert_eq!(usage.allocations, 4);
            println!(
                "capacity {label} {bound} {slots} {} {} {staging} {group_headers} {} {} {} {}",
                window.sender.max_original(),
                size_of::<GroupHeader>(),
                arena.capacity(),
                scratch.capacity(),
                plan.capacity_bytes(),
                usage.allocations
            );
        }
        Ok(())
    }
}

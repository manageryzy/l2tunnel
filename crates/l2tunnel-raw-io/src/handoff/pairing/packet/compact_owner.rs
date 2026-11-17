//! Same raw owners and physical receipts with one external Records protector.
use super::super::compact::{
    BootstrapDirection, FinalAcceptance, FinalControl, FinalInput, FinalKind, FinalMetadata,
    FinalOutputToken,
};
use super::*;

impl<I: PacketIo + Send + 'static> PacketCarrier<I> {
    /// Select final Records after real inner membership under the original setup cap.
    /// The caller binds `binding` in that authenticated session. The immutable
    /// predicate admits only original Noise/member tail grammar under the retained
    /// exporter, and cannot extend its original deadline. Existing ciphertext,
    /// arrivals and physical receipts remain owned unchanged.
    pub fn enable_final_records(
        &mut self,
        binding: [u8; 32],
        bootstrap_filter: impl Fn(BootstrapDirection, &[u8]) -> bool + Send + Sync + 'static,
    ) -> Result<(), Error> {
        self.check_live()?;
        if !self.ready || self.final_context.is_some() || binding == [0; 32] {
            return Err(Error::Configuration);
        }
        if Instant::now() >= self.deadline {
            return Err(self.fail(Error::Expired));
        }
        if self
            .records
            .iter()
            .any(|record| !bootstrap_filter(BootstrapDirection::Incoming, &record.bytes))
        {
            return Err(Error::Proof);
        }
        for lane in self.lanes.iter().flatten() {
            let state = lock(&lane.io.state)?;
            if state.final_context.is_some()
                || state.fence.is_none()
                || state.incoming.iter().any(|cell| {
                    !cell.header.kind.control()
                        && !bootstrap_filter(BootstrapDirection::Incoming, &cell.body)
                })
                || lane.early.as_ref().is_some_and(|cell| {
                    !cell.header.kind.control()
                        && !bootstrap_filter(BootstrapDirection::Incoming, &cell.body)
                })
            {
                return Err(Error::Proof);
            }
        }
        let context = hash_parts(
            b"l2tunnel/raw-final-record-context/v1\0",
            &[
                &binding,
                &self.transaction,
                &self.info.transcript_digest,
                &self.policy_digest,
                &self.armed,
                &self.commit_proof.ok_or(Error::Proof)?,
            ],
        );
        let filter: super::super::compact::BootstrapFilter = Arc::new(bootstrap_filter);
        for lane in self.lanes.iter().flatten() {
            let mut state = lock(&lane.io.state)?;
            state.final_context = Some(context);
            state.bootstrap_filter = Some(filter.clone());
        }
        self.final_context = Some(context);
        Ok(())
    }
    /// True only after explicit installation on this original carrier owner.
    pub const fn final_records_enabled(&self) -> bool {
        self.final_context.is_some()
    }
    /// Physical final geometry; original bootstrap geometry remains independently available.
    pub fn final_geometry(&self) -> Result<RecordGeometry, Error> {
        self.check()?;
        self.final_context.ok_or(Error::Configuration)?;
        self.policy.final_record_geometry()
    }
    /// Preflight one exact final packet before the sole Records sealer consumes a nonce.
    /// Reserves the existing lane output slot, without allocating sequence space.
    pub fn prepare_final_record(
        &mut self,
        lane: PairLane,
        kind: FinalKind,
        protected_bytes: usize,
    ) -> Result<FinalOutputToken, Error> {
        if kind == FinalKind::CarrierControl {
            return Err(Error::Configuration);
        }
        self.prepare_final_inner(lane, kind, None, protected_bytes)
    }
    /// Prepare a strong raw-control arm through the same original lane/quota/token.
    pub fn prepare_final_control(
        &mut self,
        lane: PairLane,
        control: FinalControl,
        protected_bytes: usize,
    ) -> Result<FinalOutputToken, Error> {
        self.prepare_final_inner(
            lane,
            FinalKind::CarrierControl,
            Some(control),
            protected_bytes,
        )
    }
    fn prepare_final_inner(
        &mut self,
        lane: PairLane,
        kind: FinalKind,
        control: Option<FinalControl>,
        protected_bytes: usize,
    ) -> Result<FinalOutputToken, Error> {
        self.check_live()?;
        let context = self.final_context.ok_or(Error::Configuration)?;
        let count = self.count();
        let index = lane.index();
        if index >= count
            || protected_bytes < 5
            || protected_bytes > self.policy.final_record_geometry()?.max_record_bytes
            || (kind == FinalKind::Data && count == 2 && (index == 0) != self.info.is_client)
        {
            return Err(Error::Configuration);
        }
        let owner = self.lanes[index].as_mut().ok_or(Error::Proof)?;
        if owner.pending.is_some()
            || owner.io.pending()
            || owner.final_prepared.is_some()
            || owner.tracked.is_some()
            || owner.completed.is_some()
        {
            return Err(Error::Busy);
        }
        match control {
            Some(FinalControl::Ping(value))
                if owner.ping.is_some_and(|pending| pending != value)
                    || (owner.ping.is_some()
                        && Instant::now().saturating_duration_since(owner.last_ping)
                            < TRANSITION_RETRY_INTERVAL) =>
            {
                return Err(Error::Busy);
            }
            Some(FinalControl::Pong(value)) if owner.pong != Some(value) => {
                return Err(Error::Configuration);
            }
            _ => {}
        }
        let state = lock(&owner.io.state)?;
        let f = state.fence.as_ref().ok_or(Error::Proof)?;
        let end = f
            .allocated
            .checked_add(protected_bytes as u64)
            .ok_or(Error::Exhausted)?;
        if end >= u64::from(u32::MAX - f.local) {
            return Err(Error::Exhausted);
        }
        let reserve = kind.reserve() * (u64::from(self.policy.mtu) - 40);
        if end
            > f.peer_retired
                .checked_add(f.peer_horizon)
                .ok_or(Error::Exhausted)?
                .saturating_sub(reserve)
        {
            return Err(Error::Busy);
        }
        let metadata = FinalMetadata {
            context,
            lane: index as u8,
            sender: if self.info.is_client { 1 } else { 2 },
            kind,
            sequence: f
                .local
                .checked_add(u32::try_from(f.allocated).map_err(|_| Error::Exhausted)?)
                .ok_or(Error::Exhausted)?,
            acknowledgment: f
                .peer
                .checked_add(u32::try_from(f.retired).map_err(|_| Error::Exhausted)?)
                .ok_or(Error::Exhausted)?,
            window: u16::try_from(f.local_horizon >> owner.proof.scale)
                .map_err(|_| Error::Proof)?,
            payload_bytes: u16::try_from(protected_bytes).map_err(|_| Error::Capacity)?,
        };
        owner.final_prepared = Some((metadata, control));
        Ok(FinalOutputToken {
            metadata,
            end,
            control,
        })
    }
    /// Release an uncommitted reservation. It never rewinds an external nonce.
    pub fn cancel_final_record(&mut self, token: FinalOutputToken) -> Result<(), Error> {
        let owner = self
            .lanes
            .get_mut(usize::from(token.metadata.lane))
            .and_then(Option::as_mut)
            .ok_or(Error::Proof)?;
        if owner.final_prepared != Some((token.metadata, token.control)) {
            return Err(Error::Proof);
        }
        owner.final_prepared = None;
        Ok(())
    }
    /// Retain exactly the once-protected bytes and allocate their sequence extent once.
    /// Physical success still requires the original `take_sent_record` receipt.
    pub fn commit_final_record(
        &mut self,
        token: FinalOutputToken,
        protected: &[u8],
    ) -> Result<RecordToken, Error> {
        self.check_live()?;
        let metadata = token.metadata;
        if self.final_context != Some(metadata.context)
            || protected.len() != metadata.payload_bytes()
            || FinalKind::inspect(protected) != Some(metadata.kind)
        {
            return Err(Error::Proof);
        }
        let owner = self
            .lanes
            .get_mut(usize::from(metadata.lane))
            .and_then(Option::as_mut)
            .ok_or(Error::Proof)?;
        if owner.final_prepared != Some((metadata, token.control))
            || owner.pending.is_some()
            || owner.io.pending()
        {
            return Err(Error::Proof);
        }
        let mut state = lock(&owner.io.state)?;
        let f = state.fence.as_ref().ok_or(Error::Proof)?;
        if u64::from(metadata.sequence.checked_sub(f.local).ok_or(Error::Proof)?) != f.allocated
            || token.end
                != f.allocated
                    .checked_add(protected.len() as u64)
                    .ok_or(Error::Exhausted)?
        {
            return Err(Error::Proof);
        }
        let mut bytes = vec![0; protected.len() + 40];
        packet::encode(
            state.config,
            metadata.sequence,
            metadata.acknowledgment,
            metadata.window,
            protected,
            &mut bytes,
        )
        .map_err(|_| Error::Proof)?;
        let retired = if metadata.kind == FinalKind::Data {
            owner.retirement_reported
        } else {
            u64::from(
                metadata
                    .acknowledgment
                    .checked_sub(f.peer)
                    .ok_or(Error::Proof)?,
            )
        };
        let kind = match token.control {
            Some(FinalControl::Window) => wire::Kind::Window,
            Some(FinalControl::Ping(value)) => {
                owner.ping = Some(value);
                owner.last_ping = Instant::now();
                wire::Kind::Ping
            }
            Some(FinalControl::Pong(value)) => {
                if owner.pong == Some(value) {
                    owner.pong = None;
                }
                wire::Kind::Pong
            }
            None if metadata.kind == FinalKind::Data => wire::Kind::Data,
            None => wire::Kind::Feedback,
        };
        state.fence.as_mut().ok_or(Error::Proof)?.allocated = token.end;
        owner.pending = Some(Pending {
            bootstrap: false,
            bytes,
            end: token.end,
            kind,
            retired,
        });
        owner.final_prepared = None;
        let receipt = RecordToken(token.end);
        owner.tracked = Some(receipt);
        Ok(receipt)
    }
    /// Callback convenience over the exact same preparation/commit path.
    pub fn stage_final_record_with(
        &mut self,
        lane: PairLane,
        kind: FinalKind,
        protected_bytes: usize,
        seal: impl FnOnce(&FinalMetadata, &mut [u8]) -> Result<(), Error>,
    ) -> Result<RecordToken, Error> {
        let token = self.prepare_final_record(lane, kind, protected_bytes)?;
        let mut bytes = vec![0; protected_bytes];
        if let Err(error) = seal(&token.metadata, &mut bytes) {
            self.cancel_final_record(token)?;
            return Err(error);
        }
        self.commit_final_record(token, &bytes)
    }
    /// Next existing raw-control obligation; this creates no packet or fresh deadline.
    pub fn poll_final_control(&mut self, lane: PairLane) -> Result<Option<FinalControl>, Error> {
        self.check_live()?;
        self.final_context.ok_or(Error::Configuration)?;
        let owner = self
            .lanes
            .get_mut(lane.index())
            .and_then(Option::as_mut)
            .ok_or(Error::Configuration)?;
        if owner.pending.is_some()
            || owner.io.pending()
            || owner.final_prepared.is_some()
            || owner.completed.is_some()
            || owner.tracked.is_some()
        {
            return Ok(None);
        }
        if owner
            .retirement_required
            .saturating_sub(owner.retirement_reported)
            >= owner.retirement_threshold()?
        {
            return Ok(Some(FinalControl::Window));
        }
        if let Some(value) = owner.pong {
            return Ok(Some(FinalControl::Pong(value)));
        }
        let interval = if owner.ping.is_some() {
            TRANSITION_RETRY_INTERVAL
        } else {
            Duration::from_secs(5)
        };
        if Instant::now().saturating_duration_since(owner.last_ping) >= interval {
            // Repeat the logical challenge, not its protected packet. The sole
            // Records owner supplies a fresh nonce and this owner supplies a new
            // raw extent. Only a matching authenticated Pong renews last_alive.
            if let Some(value) = owner.ping {
                return Ok(Some(FinalControl::Ping(value)));
            }
            let mut value = [0; 8];
            SystemRandom::new()
                .fill(&mut value)
                .map_err(|_| Error::Proof)?;
            return Ok(Some(FinalControl::Ping(value)));
        }
        Ok(None)
    }
    /// Earliest original arrival among already bounded, unverified final candidates.
    ///
    /// This timestamp grants only bounded processing order, not authentication,
    /// liveness, delivery or retirement authority. It performs no receive work.
    pub fn earliest_final_candidate_at(&self) -> Result<Option<Instant>, Error> {
        self.check()?;
        let mut earliest = None;
        for lane in self.lanes.iter().flatten() {
            for cell in &lock(&lane.io.state)?.incoming {
                if cell.final_metadata.is_some() {
                    earliest = Some(
                        earliest
                            .map_or(cell.received_at, |time: Instant| time.min(cell.received_at)),
                    );
                }
            }
        }
        Ok(earliest)
    }
    /// Borrow one candidate after read-only raw preflight, before Records replay commits.
    /// Bounded carrier/control/bulk turns grant verification attempts only. The
    /// selected candidate stays pinned until its verifier verdict consumes it.
    /// Drop this guard before committing or polling any raw I/O.
    pub fn final_input(&self, lane: PairLane) -> Result<Option<FinalInput<'_>>, Error> {
        self.check()?;
        self.final_context.ok_or(Error::Configuration)?;
        let owner = self
            .lanes
            .get(lane.index())
            .and_then(Option::as_ref)
            .ok_or(Error::Configuration)?;
        let mut state = lock(&owner.io.state)?;
        loop {
            let Some(index) = state.select_final_candidate()? else {
                return Ok(None);
            };
            let cell = &state.incoming[index];
            let metadata = cell.final_metadata.ok_or(Error::Proof)?;
            let received_at = cell.received_at;
            if state.validate_final(metadata).is_ok() {
                return Ok(Some(FinalInput {
                    metadata,
                    received_at,
                    state,
                    index,
                }));
            }
            state.consume_final_candidate(index)?;
            state.reject_final()?;
        }
    }
    /// Commit the sole verifier's result for exactly the previously inspected candidate.
    /// Rejection consumes no raw range/credit; Data never advances peer retirement.
    pub fn commit_final_input(
        &mut self,
        lane: PairLane,
        metadata: FinalMetadata,
        verdict: Option<FinalAcceptance<()>>,
    ) -> Result<(), Error> {
        self.check_live()?;
        let owner = self
            .lanes
            .get_mut(lane.index())
            .and_then(Option::as_mut)
            .ok_or(Error::Configuration)?;
        let mut state = lock(&owner.io.state)?;
        let index = state.selected_final_candidate(metadata)?;
        let Some(verdict) = verdict else {
            state.consume_final_candidate(index)?;
            state.reject_final()?;
            return Ok(());
        };
        if (metadata.kind != FinalKind::Data && !verdict.authenticated)
            || (metadata.kind == FinalKind::CarrierControl) != verdict.control.is_some()
        {
            return Err(Error::Proof);
        }
        let retired = state.commit_final(metadata)?;
        let received_at = state.consume_final_candidate(index)?.received_at;
        drop(state);
        match verdict.control {
            Some(FinalControl::Window) => {}
            // A freshly authenticated retry must recreate the reply obligation
            // after a lost Pong. Exact packet replays never reach this commit.
            Some(FinalControl::Ping(value)) => owner.pong = Some(value),
            Some(FinalControl::Pong(value)) => {
                if owner.ping == Some(value) {
                    owner.ping = None;
                    owner.last_alive = received_at;
                }
            }
            None => owner.retirement_required = retired,
        }
        Ok(())
    }
    /// Narrow bootstrap-only resend on the original exporter until its original cap.
    pub fn stage_bootstrap_record_tracked(
        &mut self,
        lane: PairLane,
        kind: RecordKind,
        bytes: &[u8],
    ) -> Result<RecordToken, Error> {
        self.check_live()?;
        self.final_context.ok_or(Error::Configuration)?;
        if Instant::now() >= self.deadline {
            return Err(Error::Expired);
        }
        let owner = self
            .lanes
            .get(lane.index())
            .and_then(Option::as_ref)
            .ok_or(Error::Configuration)?;
        if lock(&owner.io.state)?
            .bootstrap_filter
            .as_ref()
            .is_none_or(|allow| !allow(BootstrapDirection::Outgoing, bytes))
        {
            return Err(Error::Configuration);
        }
        if owner.completed.is_some() || owner.tracked.is_some() {
            return Err(Error::Busy);
        }
        self.stage_bootstrap_inner(lane, kind, bytes)?;
        let owner = self.lanes[lane.index()].as_mut().ok_or(Error::Proof)?;
        let token = RecordToken(owner.pending.as_ref().ok_or(Error::Proof)?.end);
        owner.tracked = Some(token);
        Ok(token)
    }
}

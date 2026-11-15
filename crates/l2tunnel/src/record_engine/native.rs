use super::*;

impl Engine {
    /// Prepare into the caller's actual free output slot under an original cap.
    ///
    /// The caller retains that slot until complete native acceptance. Repeated
    /// preparation while pending never rewrites it or renews its deadline.
    pub fn prepare_native(
        &mut self,
        now: Tick,
        work: usize,
        original_deadline: Tick,
        output: &mut [u8],
    ) -> Result<NativePreparation, Error> {
        self.advance(now)?;
        if let Some(pending) = self.pending {
            // The actual receiver may own an earlier expiry than the external
            // stall cap. Service that owner before promising the slot is live.
            if let Err(error) = self.owner.tick(now) {
                return self.fail(error);
            }
            return Ok(NativePreparation::AlreadyPending(pending));
        }
        if work == 0 {
            return Err(Error::Work);
        }
        if output.len() < self.native_max {
            return Err(Error::Output {
                required: self.native_max,
            });
        }
        let deadline = Tick(
            now.0
                .checked_add(self.limits.stall_micros)
                .ok_or(Error::Arithmetic)?,
        )
        .min(original_deadline);
        if now >= deadline {
            return Err(Error::Expired);
        }
        let serial = self
            .statistics
            .prepared
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        // Refuse before extraction/device submission if a later whole-write
        // receipt cannot be represented. One pending slot prevents a competing
        // successful commit from consuming this counter capacity.
        self.statistics
            .committed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        self.native_counts
            .preflight_prepare(self.receive_channels)?;
        let channel =
            receiver::ChannelId(u8::try_from(self.next_channel).map_err(|_| Error::Invariant)?);
        let next_channel = if self.next_channel + 1 == self.receive_channels {
            0
        } else {
            self.next_channel + 1
        };
        let step = match self.owner.extract(now, channel, work, deadline, output) {
            Ok(step) => step,
            Err(error) => return self.fail(error),
        };
        self.next_channel = next_channel;
        match step {
            NativeStep::Idle => Ok(NativePreparation::Idle),
            NativeStep::Progress => Ok(NativePreparation::Progress),
            NativeStep::Ready {
                identity,
                bytes,
                early,
            } => {
                // A retained record's real expiry can precede the external
                // first-prepare stall cap. Recovery retry timers are separate.
                let deadline = match self.owner.pending_deadline() {
                    Some(actual) if actual < duration(deadline) => {
                        Tick(u64::try_from(actual.as_micros()).map_err(|_| Error::Arithmetic)?)
                    }
                    _ => deadline,
                };
                let prepared = PreparedNative {
                    token: NativeToken {
                        context: self.context,
                        digest: self.digest,
                        serial,
                        identity,
                        rolling: match &self.owner {
                            Owner::Rolling(endpoint) => {
                                Some(endpoint.pending_native().ok_or(Error::Invariant)?.token())
                            }
                            _ => None,
                        },
                    },
                    bytes,
                    early,
                    deadline,
                };
                if let Err(error) = self.native_counts.prepare(identity, self.receive_channels) {
                    return self.fail(error);
                }
                self.statistics.prepared = serial;
                self.pending = Some(prepared);
                Ok(NativePreparation::Ready(prepared))
            }
        }
    }

    /// Observe immutable retained metadata; the caller still owns its exact bytes.
    pub const fn pending_native(&self) -> Option<PreparedNative> {
        self.pending
    }

    /// Acknowledge one whole native write using the issuing Engine's exact token.
    ///
    /// Stale tokens cannot clear another pending slot. This trusted local call
    /// does not mint peer authentication or a transaction-bank drain fence.
    pub fn commit_native(&mut self, now: Tick, token: NativeToken) -> Result<(), Error> {
        if !self.pending.is_some_and(|pending| pending.token == token) {
            return Err(Error::Token);
        }
        let next = self
            .statistics
            .committed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let pending = self.pending.ok_or(Error::Token)?;
        let (channel, committed) = self
            .native_counts
            .next_commit(pending.token.identity, self.receive_channels)?;
        let timing = self.advance(now);
        // The caller has already observed a complete physical write. Record
        // that receipt once even if subsequent authoritative cleanup is fatal.
        self.statistics.committed = next;
        self.native_counts.commit(channel, committed);
        self.pending = None;
        if matches!(&self.owner, Owner::Rolling(_)) {
            let result = self.owner.commit(now);
            timing?;
            return match result {
                Ok(()) => Ok(()),
                Err(error) => self.fail(error),
            };
        }
        timing?;
        match self.owner.commit(now) {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
}

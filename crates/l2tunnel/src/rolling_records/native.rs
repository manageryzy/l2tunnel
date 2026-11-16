use super::*;

/// Local immutable identity, unrelated to peer receipts or native record counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeToken {
    instance: u64,
    scope: receiver::Scope,
    digest: crate::core::ConfigDigest,
    stream: u32,
    serial: u64,
    identity: receiver::RecordIdentity,
}
impl NativeToken {
    /// Actual native body identity, excluding any separate header context.
    pub fn identity(self) -> receiver::RecordIdentity {
        self.identity
    }
}
/// Actual native bytes are in caller storage until one complete physical write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedNative {
    token: NativeToken,
    bytes: usize,
    early: bool,
    pub(super) deadline: Tick,
}
impl PreparedNative {
    /// Exact token required to acknowledge this prepared packet.
    pub fn token(self) -> NativeToken {
        self.token
    }
    /// Exact original body identity; contexts are distinct records.
    pub fn identity(self) -> receiver::RecordIdentity {
        self.token.identity
    }
    /// Initialized original byte count in caller output.
    pub fn bytes(self) -> usize {
        self.bytes
    }
    /// Actual codec indication of independent-short out-of-order delivery.
    pub fn early(self) -> bool {
        self.early
    }
    /// Original record expiry capped by first prepare and external deadline.
    pub fn deadline(self) -> Tick {
        self.deadline
    }
}
/// Bounded actual record preparation, retaining one exact token until completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePreparation {
    /// This selected channel has no complete eligible original packet.
    Idle,
    /// Bounded context/tombstone work progressed without native output.
    Progress,
    /// Newly initialized caller output awaits physical acceptance.
    Ready(PreparedNative),
    /// Same retained packet; caller output was not overwritten or deadline renewed.
    AlreadyPending(PreparedNative),
}
impl<P: RecoveryPolicy> Endpoint<P> {
    /// Prepare one real reconstructed native body directly into caller custody.
    /// Full configured queues remain separate from this one pending codec token.
    pub fn prepare_native(
        &mut self,
        now: Tick,
        work: usize,
        original_deadline: Tick,
        output: &mut [u8],
    ) -> Result<NativePreparation, Error> {
        self.advance(now)?;
        if let Some(pending) = self.prepared_native {
            return Ok(NativePreparation::AlreadyPending(pending));
        }
        if work == 0 {
            return Err(Error::Configuration);
        }
        let maximum = self.receive_config.receiver.body.max_frame_bytes;
        if output.len() < maximum {
            return Err(Error::Output { required: maximum });
        }
        let deadline = Tick(
            now.0
                .checked_add(self.config.native_stall_micros)
                .ok_or(Error::Arithmetic)?,
        )
        .min(original_deadline);
        if now >= deadline {
            return Err(Error::Expired);
        }
        let next = self.next_native.checked_add(1).ok_or(Error::Arithmetic)?;
        self.statistics
            .committed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let channel =
            receiver::ChannelId(u8::try_from(self.next_channel).map_err(|_| Error::Identity)?);
        let prepared = match self.records.prepare(channel, receiver_tick(now), work) {
            Ok(prepared) => prepared,
            Err(error) => return self.fail(Error::Receiver(error)),
        };
        self.next_channel = if self.next_channel + 1 == self.receive_config.receiver.channels {
            0
        } else {
            self.next_channel + 1
        };
        match prepared {
            receiver::Prepared::Idle => Ok(NativePreparation::Idle),
            receiver::Prepared::Progress => Ok(NativePreparation::Progress),
            receiver::Prepared::Ready => {
                let delivery = self.records.pending().ok_or(Error::Identity)?;
                let deadline = self
                    .records
                    .pending_deadline()
                    .map_or(deadline, |actual| Tick(actual.0).min(deadline));
                if now >= deadline {
                    return self.fail(Error::Expired);
                }
                let bytes = delivery.bytes.len();
                if bytes > maximum {
                    return self.fail(Error::Identity);
                }
                let token = NativeToken {
                    instance: self.instance,
                    scope: self.receive_scope,
                    digest: self.digest,
                    stream: self.stream,
                    serial: self.next_native,
                    identity: receiver::RecordIdentity {
                        channel: delivery.channel,
                        record: delivery.record,
                    },
                };
                let prepared = PreparedNative {
                    token,
                    bytes,
                    early: delivery.early,
                    deadline,
                };
                output[..bytes].copy_from_slice(delivery.bytes);
                self.next_native = next;
                self.prepared_native = Some(prepared);
                Ok(NativePreparation::Ready(prepared))
            }
        }
    }
    /// Observe immutable pending metadata without refreshing age or output.
    pub fn pending_native(&self) -> Option<PreparedNative> {
        self.prepared_native
    }
    /// Record one complete caller-observed native write with the issuing token.
    /// Stale tokens cannot mutate time/custody; physical observation is retained
    /// once even when subsequent original-expiry/cleanup validation fails.
    pub fn commit_native(&mut self, now: Tick, token: NativeToken) -> Result<(), Error> {
        if !self
            .prepared_native
            .is_some_and(|pending| pending.token == token)
        {
            return Err(Error::Token);
        }
        let committed = self
            .statistics
            .committed
            .checked_add(1)
            .ok_or(Error::Arithmetic)?;
        let timing = self.advance(now);
        self.statistics.committed = committed;
        self.prepared_native = None;
        timing?;
        if let Err(error) = self.records.commit_delivery(receiver_tick(now)) {
            return self.fail(Error::Receiver(error));
        }
        self.receive_progress = true;
        Ok(())
    }
}

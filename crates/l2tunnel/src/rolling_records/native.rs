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
    /// Actual codec indication of out-of-order native delivery.
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
/// Requested and effective delivery policy of one endpoint generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryStatus {
    /// Requested release of the receive direction.
    pub requested_release: NativeRelease,
    /// Effective release of the receive direction after default resolution.
    pub effective_release: EffectiveRelease,
    /// Return guard of the send direction.
    pub guard: ReturnGuardStatus,
}
impl<P: RecoveryPolicy> Endpoint<P> {
    /// Requested/effective release order and return guard of this generation.
    pub fn delivery_status(&self) -> DeliveryStatus {
        DeliveryStatus {
            requested_release: self.receive_config.native_release,
            effective_release: self.receive_config.effective_release(),
            guard: self.return_guard.status(),
        }
    }
    /// Current generation's receiver-side bounded TCP reordering observations.
    pub fn native_reorder_status(&self) -> Option<NativeReorderStatus> {
        self.fin_order.hold_status()
    }
    /// Requested/effective return guard of the send direction and its window.
    pub fn return_guard_status(&self) -> ReturnGuardStatus {
        self.return_guard.status()
    }
    /// Add delivered peer bytes without a native packet, for guard tests.
    #[cfg(test)]
    pub(super) fn observe_delivered_for_test(&mut self, now: Tick, bytes: usize) {
        self.return_guard.delivered(now, bytes);
    }
    /// Add accepted never-shed bytes without an output, for guard tests.
    #[cfg(test)]
    pub(super) fn observe_required_for_test(&mut self, now: Tick, bytes: usize) {
        self.return_guard
            .sent(now, return_guard::Class::Required, bytes);
    }
    /// Requested and effective native release order of the receive direction.
    pub fn native_release_status(&self) -> (NativeRelease, EffectiveRelease) {
        (
            self.receive_config.native_release,
            self.receive_config.effective_release(),
        )
    }
    /// Carry pending local halves across the authenticated generation switch.
    pub(crate) fn inherit_fin_order(&mut self, previous: &Self) {
        self.fin_order.inherit(&previous.fin_order);
    }

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
        let cursor =
            receiver::ChannelId(u8::try_from(self.next_channel).map_err(|_| Error::Identity)?);
        let channel = self.records.next_retained_channel(cursor).unwrap_or(cursor);
        let policy = self.receive_config.native_policy;
        let result = if self.fin_order.holds_enabled() {
            // The codec calls its dependency query and decision serially. Borrow
            // only for each individual call so physical commit retains sole custody.
            let ordering = std::cell::RefCell::new(&mut self.fin_order);
            self.records.prepare_with_native_ordering(
                channel,
                receiver_tick(now),
                work,
                |token| ordering.borrow().changed(token),
                |frame, short, early| {
                    ordering
                        .borrow_mut()
                        .held_ip_decision(policy, frame, now.0, short, early)
                },
            )
        } else if self.fin_order.tracks_payload()
            && policy.is_ip()
            && self.receive_config.effective_release() == EffectiveRelease::FlowOrdered
        {
            self.records.prepare_with_independent_packets(
                channel,
                receiver_tick(now),
                work,
                |token| self.fin_order.changed(token),
                |frame, short| {
                    self.fin_order
                        .flow_ordered_ip_decision(policy, frame, now.0, short)
                },
            )
        } else if self.fin_order.tracks_payload() && policy.is_ip() {
            self.records.prepare_with_independent_packets(
                channel,
                receiver_tick(now),
                work,
                |token| self.fin_order.changed(token),
                |frame, short| {
                    self.fin_order
                        .independent_ip_decision(policy, frame, now.0, short)
                },
            )
        } else if self.fin_order.tracks_payload() {
            self.records.prepare_with_early_dependencies(
                channel,
                receiver_tick(now),
                work,
                |token| self.fin_order.changed(token),
                |frame| self.fin_order.decision(policy, frame, now.0),
            )
        } else {
            self.records.prepare(channel, receiver_tick(now), work)
        };
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(error) => return self.fail(Error::Receiver(error)),
        };
        self.next_channel = if u16::from(channel.0) + 1 == self.receive_config.receiver.channels {
            0
        } else {
            u16::from(channel.0) + 1
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
                    let identity = receiver::RecordIdentity {
                        channel: delivery.channel,
                        record: delivery.record,
                    };
                    self.note_expiry(
                        expiry::LocalOwner::Native,
                        now,
                        deadline,
                        None,
                        Some(identity),
                    );
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
        let delivered = self.prepared_native.map_or(0, PreparedNative::bytes);
        self.prepared_native = None;
        timing?;
        self.return_guard.delivered(now, delivered);
        if let Some(delivery) = self.records.pending()
            && self.fin_order.tracks_payload()
        {
            self.fin_order.native_commit(
                self.receive_config.native_policy,
                delivery.bytes,
                delivery.early,
                now.0,
            );
        }
        if let Err(error) = self.records.commit_delivery(receiver_tick(now)) {
            return self.fail(Error::Receiver(error));
        }
        self.receive_progress = true;
        Ok(())
    }
}

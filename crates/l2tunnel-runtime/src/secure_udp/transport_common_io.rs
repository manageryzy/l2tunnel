//! Same-loop Common packet service; security and physical custody stay singular.
use super::*;
use l2tunnel::{record_bank, record_configuration as configuration, record_engine as engine};
use l2tunnel_reliable::{OutboundBudget, RecordKind};

impl Driver {
    /// Called once per sole-loop turn, never from per-packet progress callbacks.
    pub(super) fn service_common_rolling(&mut self, now: u64) -> io::Result<()> {
        let Some(work) = self.config.rolling_work else {
            return Ok(());
        };
        if self.common.is_none() || !self.check_expiry(now)? {
            return Ok(());
        }
        for epoch in self.common_epochs().into_iter().flatten() {
            let step = self
                .common_state_mut()?
                .entry(epoch)?
                .step(engine::Tick(now), work)
                .map_err(protocol)?;
            if let Some(step) = step {
                let width = usize::from(
                    self.common_state()?
                        .engine(epoch)?
                        .configuration()
                        .descriptor()
                        .local(common_contract::mg_role(self.info.role))
                        .receive()
                        .channels(),
                );
                let runtime = self
                    .common
                    .as_mut()
                    .ok_or_else(|| protocol("rolling service owner"))?;
                runtime.rolling_scheduler_steps = runtime.rolling_scheduler_steps.saturating_add(2);
                for (total, (sent, received)) in runtime.rolling_work_used.iter_mut().zip([
                    (step.send.field, step.receive.work.field),
                    (step.send.copies, step.receive.work.copies),
                    (step.send.metadata, step.receive.work.metadata),
                ]) {
                    *total = total
                        .saturating_add(sent as u64)
                        .saturating_add(received as u64);
                }
                if step.source_handed {
                    runtime.native_work[(epoch.0 % 2) as usize] = width;
                }
            }
        }
        Ok(())
    }
    pub(super) fn has_transactions(&self) -> bool {
        self.generic.is_some() || self.common.is_some()
    }
    pub(super) fn observation_dirty(&self) -> bool {
        self.generic.as_ref().is_some_and(|r| r.observation_dirty)
            || self.common.as_ref().is_some_and(|r| r.observation_dirty)
    }
    pub(super) fn clear_observation_dirty(&mut self) {
        if let Some(r) = &mut self.generic {
            r.observation_dirty = false;
        }
        if let Some(r) = &mut self.common {
            r.observation_dirty = false;
        }
    }
    pub(super) fn native_deliverable(&self) -> io::Result<bool> {
        if self.common.is_some() {
            let state = self.common_state()?;
            let runtime = self
                .common
                .as_ref()
                .ok_or_else(|| protocol("common scan contract"))?;
            Ok(self.common_epochs().into_iter().flatten().any(|epoch| {
                runtime.native_work[(epoch.0 % 2) as usize] > 0
                    && state
                        .engine(epoch)
                        .is_ok_and(|e| e.pending_native().is_none())
            }))
        } else {
            Ok(self
                .owner
                .engine(core::Epoch(self.feedback_scope.epoch.0))?
                .deliverable())
        }
    }
    pub(super) fn common_epochs(&self) -> [Option<core::Epoch>; 2] {
        let Ok(state) = self.common_state() else {
            return [None, None];
        };
        let active = state.peer().active_epoch();
        let other = state.peer().operation().map(|op| {
            if op.origin().epoch == active {
                op.ticket().epoch
            } else {
                op.origin().epoch
            }
        });
        let mut result = [None, None];
        for epoch in [Some(active), other].into_iter().flatten() {
            if !result.contains(&Some(epoch))
                && state.peer().reader(epoch).is_some()
                && state.engine(epoch).is_ok()
                && let Some(slot) = result.iter_mut().find(|slot| slot.is_none())
            {
                *slot = Some(epoch);
            }
        }
        result
    }
    pub(super) fn can_admit_common_native(&self) -> io::Result<bool> {
        let state = self.common_state()?;
        let engine = state.engine(core::Epoch(self.source_scope.epoch.0))?;
        let policy = engine
            .configuration()
            .descriptor()
            .local(common_contract::mg_role(self.info.role))
            .send()
            .common()
            .pipeline();
        let usage = engine.queue_usage();
        Ok(state.can_admit_data()
            && usage.packets < policy.queue.packets
            && policy.queue.bytes.saturating_sub(usage.bytes)
                >= engine
                    .configuration()
                    .descriptor()
                    .local(common_contract::mg_role(self.info.role))
                    .send()
                    .max_native())
    }
    pub(super) fn read_common_native<D: PacketDevice<Error = io::Error> + AsRawFd>(
        &mut self,
        ready: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, D>,
        output: &mut [u8],
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        let before = sample()?;
        self.progress_common(before)?;
        if !self.check_expiry(before)? || !self.can_admit_common_native()? {
            return Ok(false);
        }
        let received = try_native_read(ready, output);
        match &received {
            Ok(Some(_)) => {
                self.performance.counters.native_read_batch_packets = self
                    .performance
                    .counters
                    .native_read_batch_packets
                    .saturating_add(1)
            }
            Ok(None) => {
                self.performance.counters.native_read_would_block = self
                    .performance
                    .counters
                    .native_read_would_block
                    .saturating_add(1)
            }
            Err(_) => {}
        }
        let now = sample()?;
        if !self.check_expiry(now)? {
            return Ok(false);
        }
        self.progress_common(now)?;
        if !self.can_admit_common_native()? {
            return Ok(false);
        }
        let Some(length) = received? else {
            return Ok(false);
        };
        let epoch = core::Epoch(self.source_scope.epoch.0);
        let maximum = self
            .common_state()?
            .engine(epoch)?
            .configuration()
            .descriptor()
            .local(common_contract::mg_role(self.info.role))
            .send()
            .max_native();
        if length == 0 || length > maximum || length > output.len() {
            self.counters.native_oversize = self.counters.native_oversize.saturating_add(1);
            return Ok(true);
        }
        let owner::DataOwner::Common(state) = &mut self.owner else {
            return Err(protocol("common ingress owner"));
        };
        state
            .entry(epoch)?
            .enqueue_borrowed(engine::Tick(now), &output[..length])
            .map_err(protocol)?;
        self.counters.native_read = self.counters.native_read.saturating_add(1);
        Ok(true)
    }
    pub(super) fn collect_common_native(&mut self, now: u64) -> io::Result<()> {
        self.progress_common(now)?;
        let mut budget = self.config.work.native_write_batch;
        for epoch in self.common_epochs().into_iter().flatten() {
            if budget == 0 {
                break;
            }
            let scope = {
                let state = self.common_state()?;
                let reader = state
                    .peer()
                    .reader(epoch)
                    .ok_or_else(|| protocol("common extraction reader"))?;
                if reader.disposition == transaction::ReadDisposition::Staged {
                    continue;
                }
                common_actions::common_scope(epoch, reader.config)?
            };
            if self
                .common_state()?
                .engine(epoch)?
                .pending_native()
                .is_some()
            {
                continue;
            }
            let index = (epoch.0 % 2) as usize;
            let remaining = self
                .common
                .as_ref()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[index];
            if remaining == 0 {
                continue;
            }
            let origin = NativeOrigin::new(&self.info, scope, records::Direction::Receive);
            let owner::DataOwner::Common(state) = &mut self.owner else {
                return Err(protocol("common extraction owner"));
            };
            let Some(mut lease) = self.native.common_mut()?.acquire() else {
                break;
            };
            budget -= 1;
            let result = state
                .entry(epoch)?
                .prepare_native(
                    engine::Tick(now),
                    self.config.work.native_write_batch,
                    engine::Tick(self.lease),
                    lease.output()?,
                )
                .map_err(protocol)?;
            self.common
                .as_mut()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[index] = remaining - 1;
            match result {
                record_bank::NativePreparation::Ready(packet) => {
                    self.common
                        .as_mut()
                        .ok_or_else(|| protocol("common scan contract"))?
                        .native_work[index] = 0;
                    lease.publish(
                        common_native::CommonNative {
                            origin,
                            token: packet.token(),
                            identity: packet.identity(),
                            deadline: packet.deadline().0,
                        },
                        now,
                        packet.bytes(),
                    )?;
                    self.performance.counters.native_pending_packets_high = self
                        .performance
                        .counters
                        .native_pending_packets_high
                        .max(self.native.len() as u64);
                    self.performance.counters.native_pending_bytes_high = self
                        .performance
                        .counters
                        .native_pending_bytes_high
                        .max(self.native.bytes() as u64);
                }
                record_bank::NativePreparation::AlreadyPending(_) => {
                    return Err(protocol(
                        "common pending token lacks its retained queue slot",
                    ));
                }
                record_bank::NativePreparation::Progress => {
                    let width = usize::from(
                        state
                            .engine(epoch)?
                            .configuration()
                            .descriptor()
                            .local(common_contract::mg_role(self.info.role))
                            .receive()
                            .channels(),
                    );
                    self.common
                        .as_mut()
                        .ok_or_else(|| protocol("common scan contract"))?
                        .native_work[index] = width;
                }
                record_bank::NativePreparation::Idle => {}
            }
        }
        Ok(())
    }
    pub(super) fn write_common_native<D: PacketDevice<Error = io::Error> + AsRawFd>(
        &mut self,
        ready: &mut tokio::io::unix::AsyncFdReadyMutGuard<'_, D>,
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        let before = sample()?;
        if !self.check_expiry(before)? {
            return Ok(false);
        }
        self.validate_common_fence()?;
        let Some(packet) = self.native.common()?.front() else {
            return Ok(false);
        };
        let metadata = *packet.metadata();
        let since = packet.since();
        let epoch = core::Epoch(metadata.origin.scope.epoch.0);
        let expected = NativeOrigin::new(
            &self.info,
            metadata.origin.scope,
            records::Direction::Receive,
        );
        let pending = self
            .common_state()?
            .engine(epoch)?
            .pending_native()
            .ok_or_else(|| protocol("common physical token lost pending Engine"))?;
        if metadata.origin != expected
            || pending.identity() != metadata.identity
            || pending.deadline().0 != metadata.deadline
        {
            return Err(protocol(
                "common physical origin/identity/deadline mismatch",
            ));
        }
        let owner::DataOwner::Common(state) = &mut self.owner else {
            return Err(protocol("common physical owner"));
        };
        if state
            .entry(epoch)?
            .pending_native()
            .is_none_or(|actual| actual.token() != metadata.token)
        {
            return Err(protocol("common issuing Bank token differs"));
        }
        let result = try_native_write(ready, packet.bytes());
        if matches!(&result, Ok(true)) {
            // Whole device acceptance is irreversible. Commit the actual token,
            // recycle bytes and count it before sampling a possibly failing clock.
            let owner::DataOwner::Common(state) = &mut self.owner else {
                return Err(protocol("common physical owner"));
            };
            let committed = state
                .entry(epoch)?
                .commit_native(engine::Tick(before), metadata.token)
                .map_err(protocol);
            self.native.complete_front()?;
            self.counters.native_written = self.counters.native_written.saturating_add(1);
            self.performance.counters.native_write_batch_packets = self
                .performance
                .counters
                .native_write_batch_packets
                .saturating_add(1);
            committed?;
            let width = usize::from(
                self.common_state()?
                    .engine(epoch)?
                    .configuration()
                    .descriptor()
                    .local(common_contract::mg_role(self.info.role))
                    .receive()
                    .channels(),
            );
            self.common
                .as_mut()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[(epoch.0 % 2) as usize] = width;
        } else if matches!(&result, Ok(false)) {
            self.performance.counters.native_write_would_block = self
                .performance
                .counters
                .native_write_would_block
                .saturating_add(1);
        }
        if !self.check_expiry_with_completion(sample()?, Some(since), Some(metadata.deadline))? {
            return Ok(false);
        }
        result
    }
    #[cfg(test)]
    pub(super) fn send_common_user(
        &mut self,
        socket: &tokio::net::UdpSocket,
        now: u64,
    ) -> io::Result<bool> {
        let origin = self.origin;
        let current = clock(origin, Instant::now())?.max(now);
        self.send_common_user_sampled(
            current,
            |bytes| socket.try_send(bytes),
            || clock(origin, Instant::now()).map(|time| time.max(now)),
        )
    }
    #[cfg(test)]
    pub(super) fn send_common_user_with(
        &mut self,
        now: u64,
        send: impl FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.send_common_user_sampled(now, send, || Ok(now))
    }
    pub(super) fn send_common_user_sampled(
        &mut self,
        now: u64,
        mut send: impl FnMut(&[u8]) -> io::Result<usize>,
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        if !self.prepare_common_wire(now)? {
            return Ok(false);
        }
        self.flush_common_wire_sampled(now, &mut send, &mut sample)
    }
    fn prepare_common_wire(&mut self, now: u64) -> io::Result<bool> {
        if self
            .common
            .as_ref()
            .is_some_and(|runtime| runtime.sealed.is_some())
        {
            return Ok(true);
        }
        let epochs = self.common_epochs();
        let runtime = self
            .common
            .as_mut()
            .ok_or_else(|| protocol("common scheduler contract"))?;
        let first = usize::from(runtime.cursor);
        runtime.cursor = !runtime.cursor;
        for offset in 0..2 {
            let Some(epoch) = epochs[(first + offset) % 2] else {
                continue;
            };
            let (scope, allow_data) = {
                let state = self.common_state()?;
                let reader = state
                    .peer()
                    .reader(epoch)
                    .ok_or_else(|| protocol("common scheduler reader"))?;
                (
                    common_actions::common_scope(epoch, reader.config)?,
                    epoch.0 == self.source_scope.epoch.0
                        && reader.disposition != transaction::ReadDisposition::Staged,
                )
            };
            let number = self.records.next_number(Class::User);
            let available = self.bucket.allowance().saturating_sub(self.reserve);
            let owner::DataOwner::Common(state) = &mut self.owner else {
                return Err(protocol("common poll owner"));
            };
            // Existing queued originals are serviced after new native ingress has
            // stopped, before Stage can capture its immutable admitted fence.
            for _ in 0..self.config.work.native_read_batch {
                if state
                    .entry(epoch)?
                    .admit_borrowed(engine::Tick(now))
                    .map_err(protocol)?
                    .is_none()
                {
                    break;
                }
            }
            let mut budget = OutboundBudget {
                packets: 1,
                wire_bytes: available,
            };
            let runtime = self
                .common
                .as_mut()
                .ok_or_else(|| protocol("common witness owner"))?;
            self.buffers
                .frame
                .resize(self.config.security.max_body_bytes, 0);
            let Some(emission) = state
                .entry(epoch)?
                .poll(
                    engine::Tick(now),
                    number.0,
                    allow_data,
                    &mut self.buffers.frame,
                    &mut budget,
                    &mut runtime.witnesses,
                )
                .map_err(protocol)?
            else {
                continue;
            };
            let carrier = state.entry(epoch)?.pending_carrier_output();
            if carrier
                .as_ref()
                .is_some_and(|token| token.emission() != emission)
            {
                return Err(protocol(
                    "common carrier witness differs from actual emission",
                ));
            }
            let sealed = if self.records.key_epoch().is_ok() {
                self.records
                    .seal_user_in_at(
                        l2tunnel::handshake::Time(now),
                        scope,
                        meta(self.outer, cover::Phase::Established),
                        &self.buffers.frame[..emission.bytes],
                        &mut self.buffers.seal,
                        &mut self.buffers.wire,
                    )
                    .map(|sealed| sealed.record)
            } else {
                self.records.seal_user_in(
                    scope,
                    meta(self.outer, cover::Phase::Established),
                    &self.buffers.frame[..emission.bytes],
                    &mut self.buffers.seal,
                    &mut self.buffers.wire,
                )
            }
            .map_err(record_error)?;
            if sealed.number != number
                || sealed.bytes.checked_add(self.ip) != Some(emission.wire_bytes)
            {
                return Err(protocol("common exact security number/wire charge differs"));
            }
            self.counters.user_number = Some(sealed.number);
            self.counters.user_generation = Some(sealed.generation);
            let mut deadline = self
                .common_state()?
                .operation_deadline()
                .map(|d| u64::try_from(d.as_micros()).map_err(invalid))
                .transpose()?
                .unwrap_or(self.lease)
                .min(self.lease);
            if carrier.is_some()
                && let Some(original) = self
                    .common_state()?
                    .engine(epoch)?
                    .deadline()
                    .map_err(protocol)?
            {
                deadline = deadline.min(original.0);
            }
            let cost = sealed.bytes.checked_add(self.ip).ok_or_else(exhausted)?;
            self.bucket.charge(cost)?;
            self.performance.sent(
                if emission.kind == engine::EmissionKind::Feedback {
                    performance::WireKind::Feedback
                } else {
                    performance::WireKind::Data
                },
                cost,
            );
            self.outer = self.outer.checked_add(1).ok_or_else(exhausted)?;
            self.counters.wire_packets = self.counters.wire_packets.saturating_add(1);
            self.counters.wire_bytes = self.counters.wire_bytes.saturating_add(cost as u64);
            let runtime = self
                .common
                .as_mut()
                .ok_or_else(|| protocol("common sealed owner"))?;
            runtime
                .wire
                .get_mut(..sealed.bytes)
                .ok_or_else(|| protocol("common sealed capacity"))?
                .copy_from_slice(&self.buffers.wire[..sealed.bytes]);
            runtime.sealed = Some(common::PendingWire {
                scope,
                sealed,
                cost,
                deadline,
                carrier,
            });
            return Ok(true);
        }
        self.performance.counters.user_not_ready_polls = self
            .performance
            .counters
            .user_not_ready_polls
            .saturating_add(1);
        Ok(false)
    }
    pub(super) fn send_common_carrier(
        &mut self,
        socket: &mut carrier::IoOwner,
        now: u64,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<bool> {
        if !self.prepare_common_wire(now)? {
            return Ok(false);
        }
        let runtime = self
            .common
            .as_ref()
            .ok_or_else(|| protocol("common carrier output owner"))?;
        let pending = runtime
            .sealed
            .as_ref()
            .ok_or_else(|| protocol("common carrier output custody"))?;
        let identity = carrier::UserIdentity {
            scope: pending.scope,
            number: pending.sealed.number,
            bytes: pending.sealed.bytes,
            deadline: self
                .origin
                .checked_add(duration(pending.deadline))
                .ok_or_else(exhausted)?,
        };
        match socket.try_user(identity, &runtime.wire[..pending.sealed.bytes])? {
            carrier::SendProgress::Pending => Ok(false),
            carrier::SendProgress::Whole { receipt, late } => {
                self.complete_common_carrier(identity, receipt, late, &mut sample)
            }
        }
    }
    pub(super) fn complete_common_carrier(
        &mut self,
        identity: carrier::UserIdentity,
        receipt: crate::secure_udp::original_datagram::SendReceipt,
        late: bool,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<bool> {
        // Physical facts are irreversible, including completion observed after a cap.
        self.counters.socket_accepted_packets =
            self.counters.socket_accepted_packets.saturating_add(1);
        self.counters.socket_accepted_ip_bytes = self
            .counters
            .socket_accepted_ip_bytes
            .saturating_add(receipt.ip_bytes as u64);
        let pending = self
            .common
            .as_mut()
            .ok_or_else(|| protocol("whole carrier write lost runtime"))?
            .sealed
            .take()
            .ok_or_else(|| protocol("whole carrier write lost pending ciphertext"))?;
        if pending.scope != identity.scope
            || pending.sealed.number != identity.number
            || pending.sealed.bytes != identity.bytes
            || receipt.datagram_bytes != identity.bytes
            || pending.cost != receipt.ip_bytes
            || !self.scope_registered(pending.scope)
        {
            return Err(protocol(
                "actual carrier completion differs from retained ciphertext",
            ));
        }
        // Sample the same sole-loop clock only after retaining the irreversible
        // receipt and removing its exact ciphertext custody. The receipt's own
        // accepted_at remains the independent physical fact, never rewritten.
        let observed = sample();
        let completed = clock(self.origin, observed);
        let at = completed.as_ref().copied().unwrap_or(u64::MAX);
        let confirmation = if let Some(token) = pending.carrier {
            self.common_state_mut()?
                .entry(core::Epoch(pending.scope.epoch.0))?
                .confirm_carrier_output(engine::Tick(at), token)
                .map_err(protocol)
        } else {
            Ok(())
        };
        completed?;
        confirmation?;
        if late
            || receipt.accepted_at >= receipt.deadline
            || observed >= receipt.deadline
            || at >= pending.deadline
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "whole carrier write crossed original cap",
            ));
        }
        self.check_expiry(at)
    }
    #[cfg(test)]
    pub(super) fn flush_common_wire_with(
        &mut self,
        now: u64,
        send: impl FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.flush_common_wire_sampled(now, send, || Ok(now))
    }
    fn flush_common_wire_sampled(
        &mut self,
        now: u64,
        mut send: impl FnMut(&[u8]) -> io::Result<usize>,
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        if !self.check_expiry(now)? {
            return Ok(false);
        }
        let Some(pending) = self
            .common
            .as_ref()
            .ok_or_else(|| protocol("common sealed owner"))?
            .sealed
            .as_ref()
        else {
            return Ok(false);
        };
        let (scope, sealed, cost, deadline) = (
            pending.scope,
            pending.sealed,
            pending.cost,
            pending.deadline,
        );
        if !self.scope_registered(scope)
            || self.records.next_number(Class::User).0 <= sealed.number.0
        {
            return Err(protocol(
                "retained Common wire lost its original security scope/number",
            ));
        }
        let runtime = self
            .common
            .as_mut()
            .ok_or_else(|| protocol("common sealed owner"))?;
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Common sealed output cap",
            ));
        }
        match send(&runtime.wire[..sealed.bytes]) {
            Ok(bytes) if bytes == sealed.bytes => {
                self.counters.socket_accepted_packets =
                    self.counters.socket_accepted_packets.saturating_add(1);
                self.counters.socket_accepted_ip_bytes = self
                    .counters
                    .socket_accepted_ip_bytes
                    .saturating_add(cost as u64);
                let pending = runtime
                    .sealed
                    .take()
                    .ok_or_else(|| protocol("whole write lost Common custody"))?;
                let sampled = sample();
                let completed = sampled.as_ref().copied().unwrap_or(u64::MAX);
                let confirmation = if let Some(token) = pending.carrier {
                    self.common_state_mut()?
                        .entry(core::Epoch(pending.scope.epoch.0))?
                        .confirm_carrier_output(engine::Tick(completed), token)
                        .map_err(protocol)
                } else {
                    Ok(())
                };
                // Whole physical ownership is permanent even if the post-write
                // sample or original cap makes the connection terminal.
                sampled?;
                confirmation?;
                if completed >= pending.deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "whole Common write crossed its original cap",
                    ));
                }
                self.check_expiry(completed)
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial Common UDP handoff",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
    pub(super) fn receive_common_user(
        &mut self,
        opened: record::Opened,
        now: u64,
    ) -> io::Result<()> {
        let epoch = core::Epoch(opened.scope.epoch.0);
        let state = self.common_state()?;
        let Some(reader) = state.peer().reader(epoch) else {
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(());
        };
        if common_actions::common_scope(epoch, reader.config)? != opened.scope
            || !self.scope_registered(opened.scope)
        {
            return Err(protocol("common authenticated reader scope differs"));
        }
        let local = reader
            .config
            .descriptor()
            .local(common_contract::mg_role(self.info.role));
        let body = &self.buffers.plain[..opened.bytes];
        let kind = match local.receive().profile() {
            configuration::DirectionProfile::Swift(_) => match body
                .first()
                .map(|lead| lead & swift::KIND_MASK)
            {
                Some(swift::KIND_SOURCE) => engine::EmissionKind::Source(engine::SourceForm::Swift),
                Some(swift::KIND_REPAIR) => engine::EmissionKind::Repair,
                Some(swift::KIND_FEEDBACK) => engine::EmissionKind::Feedback,
                _ => return Err(protocol("unknown common Swift body")),
            },
            configuration::DirectionProfile::Aligned(config) => {
                classify(body, config.recovery, self.info.role)?
            }
            configuration::DirectionProfile::Packed(config) => {
                classify(body, config.base.recovery, self.info.role)?
            }
            configuration::DirectionProfile::Rolling { config, .. } => {
                let recovery = config.scheduler.recovery;
                let configuration::DirectionProfile::Rolling { config: send, .. } =
                    local.send().profile()
                else {
                    return Err(protocol("rolling directional family mismatch"));
                };
                if l2tunnel_fec::rolling::scheduler::decode_feedback(send.scheduler.recovery, body)
                    .is_ok()
                {
                    engine::EmissionKind::Feedback
                } else {
                    match l2tunnel_fec::rolling::wire::inspect_with(
                        recovery,
                        config.scheduler.source_wire,
                        body,
                    )
                    .map_err(protocol)?
                    {
                        l2tunnel_fec::rolling::wire::View::Source { .. } => {
                            engine::EmissionKind::Source(engine::SourceForm::SystematicFec)
                        }
                        l2tunnel_fec::rolling::wire::View::Repair(_) => {
                            engine::EmissionKind::Repair
                        }
                    }
                }
            }
        };
        if reader.disposition == transaction::ReadDisposition::Staged
            && kind != engine::EmissionKind::Feedback
        {
            return Err(protocol(
                "staged common generation cannot admit native-producing data",
            ));
        }
        let width = usize::from(local.receive().channels());
        self.common
            .as_mut()
            .ok_or_else(|| protocol("common scan contract"))?
            .native_work[(epoch.0 % 2) as usize] = width;
        let owner::DataOwner::Common(state) = &mut self.owner else {
            return Err(protocol("common receive owner"));
        };
        match state.entry(epoch)?.accept_authenticated(
            engine::Tick(now),
            opened.number.0,
            kind,
            &mut self.buffers.plain[..opened.bytes],
        ) {
            Ok(()) => Ok(()),
            Err(record_bank::Error::Engine(engine::Error::Aligned(error)))
                if error.is_backpressure() =>
            {
                self.counters.native_backpressure_drops =
                    self.counters.native_backpressure_drops.saturating_add(1);
                Ok(())
            }
            Err(record_bank::Error::Engine(engine::Error::Rolling(error)))
                if error.is_backpressure() =>
            {
                self.counters.native_backpressure_drops =
                    self.counters.native_backpressure_drops.saturating_add(1);
                Ok(())
            }
            Err(error) => Err(protocol(error)),
        }
    }
    pub(super) fn wake_common(&self, now: u64) -> io::Result<Instant> {
        self.wake_common_with_custody(now, false, false)
    }
    pub(super) fn wake_common_with_custody(
        &self,
        now: u64,
        held_user: bool,
        held_control: bool,
    ) -> io::Result<Instant> {
        let mut wake = self.lease;
        if !held_user
            && let Some(pending) = self
                .common
                .as_ref()
                .and_then(|runtime| runtime.sealed.as_ref())
        {
            wake = wake.min(now).min(pending.deadline);
        }
        if self.control_work || self.control.ready_nontransaction()? {
            wake = wake.min(now);
        }
        for at in [
            self.challenge.as_ref().map(|c| c.deadline),
            self.native.common_deadline(),
            self.native
                .oldest_since()
                .map(|at| add(at, self.config.native.stall_timeout))
                .transpose()?,
            self.next_report,
            self.common_state()?
                .next_deadline()
                .map(|d| u64::try_from(d.as_micros()).map_err(invalid))
                .transpose()?,
            Some(u64::try_from(self.control.expiry().as_micros()).map_err(invalid)?),
            self.control
                .pending_deadline()
                .map(|d| u64::try_from(d.as_micros()).map_err(invalid))
                .transpose()?,
        ]
        .into_iter()
        .flatten()
        {
            wake = wake.min(at);
        }
        if self.challenge.is_none() {
            wake = wake.min(self.next_ping);
        }
        if self.ingress.left == 0 {
            wake = wake.min(self.ingress.refill);
        }
        if !held_control {
            wake = wake.min(
                u64::try_from(self.control.deadline().as_micros())
                    .map_err(invalid)?
                    .max(self.bucket.ready_at(self.reserve)?),
            );
        }
        for epoch in self.common_epochs().into_iter().flatten() {
            let engine = self.common_state()?.engine(epoch)?;
            if engine.work_pending().map_err(protocol)? {
                wake = wake.min(now);
            }
            if held_user {
                if let Some(at) = engine.deadline().map_err(protocol)? {
                    wake = wake.min(at.0);
                }
                continue;
            }
            let local = engine
                .configuration()
                .descriptor()
                .local(common_contract::mg_role(self.info.role));
            let overhead = self
                .common
                .as_ref()
                .ok_or_else(|| protocol("common wake contract"))?
                .contract
                .geometry()
                .forward_overhead_bytes;
            // Drain excludes user-data custody, not later duplicate-triggered
            // feedback. Every retained reader keeps its actual small ACK wake.
            if let Some((at, bytes)) = engine.feedback_opportunity().map_err(protocol)? {
                let required = bytes
                    .checked_add(overhead)
                    .and_then(|v| v.checked_add(self.reserve))
                    .ok_or_else(exhausted)?;
                wake = wake.min(at.0.max(self.bucket.ready_at(required)?));
            }
            // Physical promotion follows the complete old-generation barrier.
            // Staged and post-promotion old readers owe no new DATA output;
            // their original maximum must not enlarge the new active burst.
            if epoch.0 != self.source_scope.epoch.0 || engine.drained().map_err(protocol)? {
                continue;
            }
            let required = common_contract::maximum_body(local.send())?
                .checked_add(overhead)
                .and_then(|v| v.checked_add(self.reserve))
                .ok_or_else(exhausted)?;
            let ready = self.bucket.ready_at(required)?;
            if engine.queue_usage().packets > 0 {
                wake = wake.min(ready);
            }
            if let Some(at) = engine.wake_at().map_err(protocol)? {
                wake = wake.min(at.0.max(ready));
            }
        }
        let mut instant = self
            .origin
            .checked_add(duration(wake))
            .ok_or_else(exhausted)?;
        if !held_control {
            for (at, bytes) in [
                (
                    self.bootstrap.deadline(),
                    self.bootstrap.max_packet_bytes() + self.ip,
                ),
                (
                    self.joining.deadline(),
                    self.joining.max_packet_bytes() + self.ip,
                ),
            ] {
                if let Some(at) = at {
                    instant = instant.min(
                        at.max(
                            self.origin
                                .checked_add(duration(self.bucket.ready_at(bytes)?))
                                .ok_or_else(exhausted)?,
                        ),
                    );
                }
            }
        }
        let floor = self
            .origin
            .checked_add(duration(now.checked_add(100).ok_or_else(exhausted)?))
            .ok_or_else(exhausted)?;
        Ok(instant.max(floor))
    }
}
fn classify(
    body: &[u8],
    config: l2tunnel_reliable::ReliableConfig,
    role: security::Role,
) -> io::Result<engine::EmissionKind> {
    let sender = if role == security::Role::Initiator {
        recovery::EndpointRole::Responder
    } else {
        recovery::EndpointRole::Initiator
    };
    let view = l2tunnel_reliable::inspect_structural(
        body,
        sender,
        config.maximum_packet_bytes().map_err(protocol)?,
        config.arq.max_source_bytes,
        config.fec.block,
    )
    .map_err(protocol)?;
    Ok(match view.kind {
        RecordKind::Source => engine::EmissionKind::Source(engine::SourceForm::DirectArq),
        RecordKind::Systematic => engine::EmissionKind::Source(engine::SourceForm::SystematicFec),
        RecordKind::Repair => engine::EmissionKind::Repair,
        RecordKind::Feedback => engine::EmissionKind::Feedback,
    })
}

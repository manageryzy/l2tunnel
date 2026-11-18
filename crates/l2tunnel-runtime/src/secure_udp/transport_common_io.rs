//! Same-loop Common packet service; security and physical custody stay singular.
use super::*;
use crate::buffer_metrics::{Reason, Site};
use l2tunnel::{record_bank, record_configuration as configuration, record_engine as engine};
use l2tunnel_reliable::OutboundBudget;

impl Driver {
    fn common_authenticated_data(&self) -> bool {
        self.common.as_deref().is_some_and(|runtime| {
            runtime.contract.proxy_binding().is_some()
                && self.records.compact_selection().protection.tag_bytes() < 16
        })
    }

    /// Check the selected strong-feedback boundary before liveness or codec
    /// mutation. Public algorithm kind bytes cannot upgrade short-check Data.
    pub(super) fn validate_common_compact_route(&self, opened: record::Opened) -> io::Result<bool> {
        if opened.class == Class::Control {
            return Ok(opened.authenticated && !opened.feedback);
        }
        let state = self.common_state()?;
        let Some(reader) = state.peer().reader(core::Epoch(opened.scope.epoch.0)) else {
            return Ok(false);
        };
        if common_actions::record_scope(reader.scope) != opened.scope {
            return Ok(false);
        }
        let body = &self.buffers.plain[..opened.bytes];
        let engine = state.engine(core::Epoch(opened.scope.epoch.0))?;
        let inspected = if engine.fragment_policy().is_some() {
            engine.inspect_fragment_kind(body)
        } else {
            engine.inspect_peer(body)
        };
        let kind = match inspected {
            Ok(kind) => kind,
            Err(_) => return Ok(false),
        };
        // Selected data checks never grant feedback authority. The negotiated
        // owner's parser validates the complete body before liveness changes.
        Ok(if kind == engine::EmissionKind::Feedback {
            opened.feedback && opened.authenticated
        } else {
            !opened.feedback && (!self.common_authenticated_data() || opened.strongly_authenticated)
        })
    }

    pub(super) fn restore_common_path(&mut self) {
        if let Some(runtime) = &mut self.common
            && runtime.path.unavailable
        {
            runtime.path.unavailable = false;
            runtime.path.retry_at_micros = None;
            runtime.path.resumptions = runtime.path.resumptions.saturating_add(1);
            runtime.observation_dirty = true;
        }
    }

    fn common_retry_attempt(&mut self, now: u64) -> io::Result<bool> {
        let interval = self.config.work.receive_interval;
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("common retry owner missing"))?;
        if runtime.path.unavailable {
            if runtime.path.retry_at_micros.is_some_and(|at| now < at) {
                return Ok(false);
            }
            let next = add(now, interval)?;
            runtime.path.retry_attempts = runtime.path.retry_attempts.saturating_add(1);
            runtime.path.retry_at_micros = Some(next);
        }
        Ok(true)
    }

    fn common_path_failure(&mut self, now: u64, kind: io::ErrorKind) -> io::Result<()> {
        let next = add(now, self.config.work.receive_interval)?;
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("common retry owner missing"))?;
        runtime.observation_dirty |= !runtime.path.unavailable;
        runtime.path.unavailable = true;
        runtime.path.send_failures = runtime.path.send_failures.saturating_add(1);
        runtime.path.last_error = Some(kind);
        runtime.path.retry_at_micros = Some(next);
        self.counters.socket_drops = self.counters.socket_drops.saturating_add(1);
        Ok(())
    }

    /// Service every current owner's bounded maintenance once per sole-loop turn,
    /// with explicit Rolling work when selected; never from per-packet callbacks.
    pub(super) fn service_common_rolling(&mut self, now: u64) -> io::Result<()> {
        let work = self.config.rolling_work;
        if self.common.is_none() || !self.check_expiry(now)? {
            return Ok(());
        }
        self.retry_common_fragment_inputs(now)?;
        for epoch in self.common_epochs().into_iter().flatten() {
            let step = if let Some(work) = work {
                self.common_state_mut()?
                    .entry(epoch)?
                    .step(engine::Tick(now), work)
                    .map_err(protocol)?
            } else {
                self.common_state_mut()?
                    .entry(epoch)?
                    .tick(engine::Tick(now))
                    .map_err(protocol)?;
                None
            };
            if let Some(step) = step {
                let visits = if step.source_handed || step.native_progress {
                    Some(self.common_state()?.engine(epoch)?.native_scan_visits())
                } else {
                    None
                };
                let runtime = self
                    .common
                    .as_deref_mut()
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
                if let Some(visits) = visits {
                    runtime.native_work[(epoch.0 % 2) as usize] = visits;
                }
            }
        }
        self.retry_common_fragment_inputs(now)?;
        self.retry_common_feedback(now)?;
        Ok(())
    }
    pub(super) fn has_transactions(&self) -> bool {
        self.common.is_some()
    }
    pub(super) fn observation_dirty(&self) -> bool {
        self.common.as_deref().is_some_and(|r| r.observation_dirty)
    }
    pub(super) fn clear_observation_dirty(&mut self) {
        if let Some(r) = &mut self.common {
            r.observation_dirty = false;
        }
    }
    pub(super) fn native_deliverable(&self) -> io::Result<bool> {
        let state = self.common_state()?;
        let runtime = self
            .common
            .as_deref()
            .ok_or_else(|| protocol("common scan contract"))?;
        Ok(self.common_epochs().into_iter().flatten().any(|epoch| {
            runtime.native_work[(epoch.0 % 2) as usize] > 0
                && state.engine(epoch).is_ok_and(|e| {
                    e.pending_native().is_none() && e.pending_native_delivery().is_none()
                })
        }))
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
        if self
            .common
            .as_deref()
            .and_then(|r| r.reuse_controller())
            .is_some_and(super::common_reuse::Controller::active)
        {
            return Ok(false);
        }
        let state = self.common_state()?;
        let engine = state.engine(core::Epoch(self.source_scope.epoch.0))?;
        let policy = engine
            .configuration()
            .descriptor()
            .local(common_contract::mg_role(self.info.role))
            .send()
            .common()
            .pipeline();
        if self.config.ack_coalescing.is_some() {
            return Ok(!self.common.as_deref().is_some_and(|runtime| {
                runtime.path.unavailable || runtime.pending_ingress.is_some()
            }) && state.can_admit_data());
        }
        let usage = engine.queue_usage();
        Ok(!self
            .common
            .as_deref()
            .is_some_and(|runtime| runtime.path.unavailable)
            && state.can_admit_data()
            && usage.packets < policy.queue.packets
            && policy.queue.bytes.saturating_sub(usage.bytes)
                >= engine
                    .configuration()
                    .descriptor()
                    .local(common_contract::mg_role(self.info.role))
                    .send()
                    .max_native())
    }
    pub(super) fn read_common_native<D: NativeDevice>(
        &mut self,
        ready: &mut NativeGuard<'_, D>,
        output: &mut [u8],
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        if self.config.ack_coalescing.is_some() {
            return self.read_common_coalesced(ready, output, sample);
        }
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
        if self.reject_retired_connection_native(epoch, &output[..length])? {
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(true);
        }
        let connection_cap = if self.connection_scope(self.source_scope)? {
            Some(add(before, self.config.native.stall_timeout)?.min(self.common_original_cap()?))
        } else {
            None
        };
        #[cfg(unix)]
        let proxy_timing = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.proxy_bridge.as_ref())
            .map(|bridge| bridge.timing())
            .transpose()?;
        #[cfg(not(unix))]
        let proxy_timing: Option<(Instant, Instant)> = None;
        let proxy_timing = proxy_timing
            .map(|(received, deadline)| {
                Ok::<_, io::Error>((clock(self.origin, received)?, clock(self.origin, deadline)?))
            })
            .transpose()?;
        let owner::DataOwner::Common(state) = &mut self.owner;
        if let Some((received, deadline)) = proxy_timing {
            state
                .entry(epoch)?
                .enqueue_proxy_borrowed(
                    engine::Tick(received),
                    engine::Tick(now),
                    &output[..length],
                    engine::Tick(deadline),
                )
                .map_err(protocol)?;
        } else if let Some(original_cap) = connection_cap {
            state
                .entry(epoch)?
                .ingest_borrowed_at(
                    engine::Tick(before),
                    engine::Tick(now),
                    &output[..length],
                    engine::Tick(original_cap),
                )
                .map_err(protocol)?;
        } else {
            state
                .entry(epoch)?
                .enqueue_borrowed(engine::Tick(now), &output[..length])
                .map_err(protocol)?;
        }
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
                common_actions::record_scope(reader.scope)
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
                .as_deref()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[index];
            if remaining == 0 {
                continue;
            }
            let origin = NativeOrigin::new(&self.info, scope, records::Direction::Receive);
            let owner::DataOwner::Common(state) = &mut self.owner;
            let Some(mut lease) = self.native.common_mut()?.acquire() else {
                if let Some(metrics) = self
                    .common
                    .as_deref_mut()
                    .and_then(|r| r.buffer_metrics.as_mut())
                {
                    // A scan lease can be refused before prepare_native proves a
                    // packet deliverable. Count the refusal without inventing a
                    // useful-output waiting interval.
                    let _ = metrics.collector().refused(
                        crate::buffer_metrics::Key {
                            site: Site::NativeOutputQueue,
                            lane: crate::buffer_metrics::Lane::Shared,
                            class: crate::buffer_metrics::Class::Shared,
                        },
                        Reason::BufferCapacity,
                        now,
                    );
                }
                break;
            };
            if let Some(runtime) = self.common.as_deref_mut() {
                runtime.buffer_event(Site::NativeOutputQueue, Reason::BufferCapacity, now, false);
            }
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
                .as_deref_mut()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[index] = remaining - 1;
            match result {
                record_bank::NativePreparation::Ready(packet) => {
                    self.common
                        .as_deref_mut()
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
                    let visits = state.engine(epoch)?.native_scan_visits();
                    self.common
                        .as_deref_mut()
                        .ok_or_else(|| protocol("common scan contract"))?
                        .native_work[index] = visits;
                }
                record_bank::NativePreparation::Idle => {}
            }
        }
        Ok(())
    }
    pub(super) fn write_common_native<D: NativeDevice>(
        &mut self,
        ready: &mut NativeGuard<'_, D>,
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        let before = sample()?;
        if !self.check_expiry(before)? {
            return Ok(false);
        }
        self.service_due_acks(before)?;
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
        let owner::DataOwner::Common(state) = &mut self.owner;
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
            let owner::DataOwner::Common(state) = &mut self.owner;
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
            let visits = self.common_state()?.engine(epoch)?.native_scan_visits();
            self.common
                .as_deref_mut()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[(epoch.0 % 2) as usize] = visits;
        } else if matches!(&result, Ok(false)) {
            self.performance.counters.native_write_would_block = self
                .performance
                .counters
                .native_write_would_block
                .saturating_add(1);
        }
        let after = sample()?;
        if let Ok(progress) = result.as_ref()
            && let Some(runtime) = self.common.as_deref_mut()
        {
            runtime.buffer_event(
                Site::NativeDeviceWrite,
                Reason::SocketWrite,
                after,
                !progress,
            );
        }
        if !self.check_expiry_with_completion(after, Some(since), Some(metadata.deadline))? {
            return Ok(false);
        }
        // A batch may include many nonblocking device writes. Each original
        // token has been settled before servicing the opposite ACK direction.
        if result.is_ok() {
            self.service_due_acks(after)?;
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
        self.prepare_common_wire_for::<super::raw_carrier::NoRaw>(now, None)
    }
    fn prepare_common_wire_for<R: super::raw_carrier::RawBacking>(
        &mut self,
        now: u64,
        raw: Option<&mut R>,
    ) -> io::Result<bool> {
        self.service_due_acks(now)?;
        if self
            .common
            .as_deref()
            .is_some_and(|runtime| runtime.sealed.is_some())
        {
            return Ok(true);
        }
        if self
            .common
            .as_deref()
            .is_some_and(|runtime| runtime.unsealed.is_some())
        {
            return self.finish_common_wire(now, raw);
        }
        let epochs = self.common_epochs();
        let runtime = self
            .common
            .as_deref_mut()
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
                    common_actions::record_scope(reader.scope),
                    epoch.0 == self.source_scope.epoch.0
                        && reader.disposition != transaction::ReadDisposition::Staged,
                )
            };
            let number = if self.common_authenticated_data() {
                self.records.next_feedback_number()
            } else {
                self.records.next_number(Class::User)
            };
            let available = self.bucket.allowance().saturating_sub(self.reserve);
            let owner::DataOwner::Common(state) = &mut self.owner;
            // Existing queued originals are serviced after new native ingress has
            // stopped, before Stage can capture its immutable admitted fence.
            for _ in 0..self.config.work.native_read_batch {
                let Some(admitted) = state
                    .entry(epoch)?
                    .admit_borrowed_diagnosed(engine::Tick(now), |refusal| {
                        if let Some(runtime) = self.common.as_deref_mut() {
                            buffer_metrics::admission_refused(runtime, now, scope, refusal);
                        }
                    })
                    .map_err(protocol)?
                else {
                    break;
                };
                if let Some(runtime) = self.common.as_deref_mut() {
                    buffer_metrics::admission_succeeded(runtime, now, scope, admitted.metadata);
                    let proxy = runtime.contract.proxy_binding().is_some();
                    if let Some(metrics) = runtime.wire_metrics.as_mut() {
                        metrics.admitted_native(admitted.permit.encoding, proxy);
                    }
                }
                #[cfg(unix)]
                if let Some(bridge) = self
                    .common
                    .as_deref()
                    .and_then(|runtime| runtime.proxy_bridge.as_ref())
                {
                    let engine::ProfileIdentity::Aligned(identity) = admitted.permit.identity
                    else {
                        return Err(protocol(
                            "Common proxy admission has another record identity",
                        ));
                    };
                    bridge.admitted(identity)?;
                }
            }
            self.buffers
                .frame
                .resize(self.config.security.max_body_bytes, 0);
            let selected_fragment = state.engine(epoch)?.fragment_policy().is_some();
            let (emission, carrier, fragment, fragment_deadline) = if selected_fragment {
                let Some((emission, fragment, deadline)) =
                    self.prepare_common_fragment(epoch, now, number.0, allow_data, available)?
                else {
                    continue;
                };
                (emission, None, Some(fragment), Some(deadline))
            } else {
                let mut budget = OutboundBudget {
                    packets: 1,
                    wire_bytes: available,
                };
                let runtime = self
                    .common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("common witness owner"))?;
                let owner::DataOwner::Common(state) = &mut self.owner;
                let mut entry = state.entry(epoch)?;
                let Some(emission) = entry
                    .poll_with_feedback_overhead(
                        engine::Tick(now),
                        number.0,
                        allow_data,
                        &mut self.buffers.frame,
                        &mut budget,
                        &mut runtime.witnesses,
                        runtime.contract.feedback_overhead_bytes()?,
                    )
                    .map_err(protocol)?
                else {
                    continue;
                };
                let carrier = entry.pending_carrier_output();
                if carrier
                    .as_ref()
                    .is_some_and(|token| token.emission() != emission)
                {
                    return Err(protocol(
                        "common carrier witness differs from actual emission",
                    ));
                }
                (emission, carrier, None, None)
            };
            let compact_feedback = emission.kind == engine::EmissionKind::Feedback;
            let mut deadline = self
                .common_state()?
                .operation_deadline()
                .map(|d| u64::try_from(d.as_micros()).map_err(invalid))
                .transpose()?
                .unwrap_or(self.lease)
                .min(self.lease);
            // Receive-cache eviction and recovery wakes do not expire unrelated
            // outgoing custody. Preserve only genuine terminal owner caps here.
            if carrier.is_some()
                && let Some(original) = self
                    .common_state()?
                    .engine(epoch)?
                    .custody_deadline()
                    .map_err(protocol)?
            {
                deadline = deadline.min(original.0);
            }
            if let Some(cap) = fragment_deadline {
                deadline = deadline.min(cap);
            }
            let cost = emission.wire_bytes;
            if fragment.is_none() {
                self.bucket.charge(cost)?;
            }
            self.performance.sent(
                if emission.kind == engine::EmissionKind::Feedback {
                    performance::WireKind::Feedback
                } else {
                    performance::WireKind::Data
                },
                cost,
            );
            self.counters.wire_packets = self.counters.wire_packets.saturating_add(1);
            self.counters.wire_bytes = self.counters.wire_bytes.saturating_add(cost as u64);
            let runtime = self
                .common
                .as_deref_mut()
                .ok_or_else(|| protocol("common sealed owner"))?;
            runtime
                .wire
                .get_mut(..emission.bytes)
                .ok_or_else(|| protocol("common pending body capacity"))?
                .copy_from_slice(&self.buffers.frame[..emission.bytes]);
            #[cfg(unix)]
            let proxy_record = runtime.proxy_bridge.as_ref().and_then(|bridge| {
                let identity = bridge.pending_identity()?;
                runtime
                    .witnesses
                    .iter()
                    .take(emission.witnesses)
                    .find(|unit| unit.identity == identity)
                    .copied()
            });
            #[cfg(not(unix))]
            let proxy_record = None;
            #[cfg(unix)]
            if proxy_record.is_some() {
                let (_, cap) = runtime
                    .proxy_bridge
                    .as_ref()
                    .ok_or_else(|| protocol("Common proxy record lost original cap"))?
                    .timing()?;
                deadline = deadline.min(clock(self.origin, cap)?);
            }
            #[cfg(unix)]
            if let Some(unit) = proxy_record
                && let Some(bridge) = &runtime.proxy_bridge
                && bridge.final_identity()? == Some(unit.identity)
            {
                if unit.index != 0 || unit.count != 1 {
                    return Err(protocol("Common final EOF is not one actual unit"));
                }
                let owner::DataOwner::Common(state) = &self.owner;
                let source = state
                    .engine(epoch)?
                    .proxy_output_source(&self.buffers.frame[..emission.bytes])
                    .map_err(protocol)?
                    .ok_or_else(|| protocol("Common final record has no actual ARQ source"))?;
                bridge.bind_final_source(unit.identity, source)?;
            }
            if let Some(trace) = runtime.compact_arq_trace.as_mut() {
                let owner::DataOwner::Common(state) = &self.owner;
                let packet = if fragment.is_none() {
                    state.engine(epoch).ok().and_then(|engine| {
                        trace.inspect(
                            engine
                                .configuration()
                                .descriptor()
                                .local(common_contract::mg_role(self.info.role)),
                            true,
                            &self.buffers.frame[..emission.bytes],
                        )
                    })
                } else {
                    None
                };
                trace.selected(
                    epoch.0,
                    if compact_feedback {
                        self.records.next_feedback_number().0
                    } else {
                        number.0
                    },
                    now,
                    packet,
                );
            }
            runtime.wire_sample =
                runtime
                    .wire_metrics
                    .as_ref()
                    .map(|_| common::wire_metrics::Sample {
                        algorithm_bytes: emission.bytes,
                        kind: emission.kind,
                        fragmented: fragment.is_some(),
                        extent: {
                            let owner::DataOwner::Common(state) = &self.owner;
                            state.engine(epoch).ok().and_then(|engine| {
                                engine
                                    .inspect_output_extent(
                                        &self.buffers.frame[..emission.bytes],
                                        emission.kind,
                                        fragment.is_some(),
                                    )
                                    .ok()
                            })
                        },
                    });
            runtime.unsealed = Some(common::PendingPlain {
                proxy_record,
                scope,
                number: if compact_feedback {
                    self.records.next_feedback_number()
                } else {
                    number
                },
                bytes: emission.bytes,
                feedback: compact_feedback,
                cost,
                deadline,
                carrier,
                fragment,
            });
            return self.finish_common_wire(now, raw);
        }
        self.performance.counters.user_not_ready_polls = self
            .performance
            .counters
            .user_not_ready_polls
            .saturating_add(1);
        Ok(false)
    }
    fn finish_common_wire<R: super::raw_carrier::RawBacking>(
        &mut self,
        now: u64,
        mut raw: Option<&mut R>,
    ) -> io::Result<bool> {
        let authenticated_data = self.common_authenticated_data();
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("common pending owner"))?;
        let pending = runtime
            .unsealed
            .as_ref()
            .ok_or_else(|| protocol("common pending body"))?;
        if now >= pending.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Common body cap",
            ));
        }
        let kind = if pending.feedback {
            record::compact::Kind::Feedback
        } else if authenticated_data {
            record::compact::Kind::AuthenticatedData
        } else {
            record::compact::Kind::Data
        };
        let capacity = self
            .records
            .capacity_for(kind, pending.bytes)
            .map_err(record_error)?;
        if capacity.packet_bytes.checked_add(self.ip) != Some(pending.cost) {
            return Err(protocol("common exact final geometry differs"));
        }
        let metadata = if let Some(raw) = raw.as_deref_mut() {
            let kind = if pending.feedback {
                l2tunnel_raw_io::handoff::pairing::packet::compact::FinalKind::Feedback
            } else {
                l2tunnel_raw_io::handoff::pairing::packet::compact::FinalKind::Data
            };
            let Some(metadata) = raw.prepare_final(kind, capacity.packet_bytes)? else {
                return Ok(false);
            };
            Some(metadata)
        } else {
            None
        };
        let body = &runtime.wire[..pending.bytes];
        let result = if let Some(metadata) = metadata {
            self.records.seal_compact_with_carrier(
                kind,
                pending.scope,
                meta(self.outer, cover::Phase::Established),
                body,
                &metadata.aad(),
                &mut self.buffers.seal,
                &mut self.buffers.wire,
            )
        } else if pending.feedback {
            self.records.seal_feedback_in(
                pending.scope,
                meta(self.outer, cover::Phase::Established),
                body,
                &mut self.buffers.seal,
                &mut self.buffers.wire,
            )
        } else if authenticated_data {
            self.records.seal_authenticated_data_in(
                pending.scope,
                meta(self.outer, cover::Phase::Established),
                body,
                &mut self.buffers.seal,
                &mut self.buffers.wire,
            )
        } else {
            self.records.seal_user_in(
                pending.scope,
                meta(self.outer, cover::Phase::Established),
                body,
                &mut self.buffers.seal,
                &mut self.buffers.wire,
            )
        };
        let sealed = match result {
            Ok(sealed) => sealed,
            Err(error) => {
                if let Some(raw) = raw {
                    raw.cancel_final()?;
                }
                return Err(record_error(error));
            }
        };
        if sealed.number != pending.number || sealed.bytes != capacity.packet_bytes {
            return Err(protocol("common exact security number/wire charge differs"));
        }
        if pending.feedback {
            runtime.compact_feedback_number = Some(sealed.number);
        } else {
            self.counters.user_number = Some(sealed.number);
            self.counters.user_generation = Some(sealed.generation);
        }
        self.outer = self.outer.checked_add(1).ok_or_else(exhausted)?;
        runtime.wire[..sealed.bytes].copy_from_slice(&self.buffers.wire[..sealed.bytes]);
        let pending = runtime
            .unsealed
            .take()
            .ok_or_else(|| protocol("common pending body lost"))?;
        runtime.sealed = Some(common::PendingWire {
            scope: pending.scope,
            sealed,
            feedback: pending.feedback,
            cost: pending.cost,
            deadline: pending.deadline,
            carrier: pending.carrier,
            fragment: pending.fragment,
            proxy_record: pending.proxy_record,
        });
        Ok(true)
    }
    pub(super) fn send_common_carrier<R: super::raw_carrier::RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        now: u64,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<bool> {
        let result = (|| -> io::Result<bool> {
            if !self.prepare_common_wire_for(now, socket.final_raw_mut())? {
                return Ok(false);
            }
            let runtime = self
                .common
                .as_deref()
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
            let ordering = self.research_physical_output(pending.scope)?;
            let progress = if ordering {
                socket.try_user_held(identity, &runtime.wire[..pending.sealed.bytes])?
            } else {
                socket.try_user(identity, &runtime.wire[..pending.sealed.bytes])?
            };
            match progress {
                carrier::SendProgress::Pending => {
                    if let Some(runtime) = self.common.as_deref_mut() {
                        runtime.buffer_event(Site::CommonUserSlot, Reason::ReceiptWait, now, true);
                    }
                    Ok(false)
                }
                carrier::SendProgress::Whole { receipt, late } => {
                    self.complete_common_carrier(identity, receipt, late, &mut sample)
                }
            }
        })();
        // A terminal User/preparation error must not hide the other lane's
        // irreversible Control receipt (or a saved User receipt). No new I/O is
        // polled here: both existing physical facts are consumed exactly once.
        let completed = self.complete_carrier_io(socket, &mut sample);
        match result {
            Err(error) => Err(error),
            Ok(sent) => completed.map(|()| sent),
        }
    }
    pub(super) fn complete_common_carrier(
        &mut self,
        identity: carrier::UserIdentity,
        receipt: impl Into<carrier::AcceptedReceipt>,
        late: bool,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<bool> {
        let receipt = receipt.into();
        // Physical facts are irreversible, including completion observed after a cap.
        self.observe_carrier_acceptance(receipt)?;
        let pending = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("whole carrier write lost runtime"))?
            .sealed
            .take()
            .ok_or_else(|| protocol("whole carrier write lost pending ciphertext"))?;
        if pending.scope != identity.scope
            || pending.sealed.number != identity.number
            || pending.sealed.bytes != identity.bytes
            || receipt.record_bytes != identity.bytes
            || receipt
                .udp_bytes
                .is_some_and(|bytes| bytes < receipt.record_bytes || bytes > receipt.charged_bytes)
            || pending.cost != receipt.charged_bytes
            || !self.scope_registered(pending.scope)
        {
            return Err(protocol(
                "actual carrier completion differs from retained ciphertext",
            ));
        }
        // Attribute lengths only after correlating the actual receipt with its
        // retained ciphertext. Genuine late acceptance still counts below.
        if let Some(runtime) = self.common.as_deref_mut()
            && let Some(sample) = runtime.wire_sample.take()
            && let Some(metrics) = runtime.wire_metrics.as_mut()
        {
            metrics.accepted(
                sample,
                receipt.record_bytes,
                receipt.boundary,
                receipt.socket_ip_bytes,
            );
        }
        // Sample the same sole-loop clock only after retaining the irreversible
        // receipt and removing its exact ciphertext custody. The receipt's own
        // accepted_at remains the independent physical fact, never rewritten.
        let observed = sample();
        let completed = clock(self.origin, observed);
        let accepted = clock(self.origin, receipt.accepted_at);
        let at = completed.as_ref().copied().unwrap_or(u64::MAX);
        let physical_at = accepted.as_ref().copied().unwrap_or(u64::MAX);
        if let Ok(at) = completed.as_ref()
            && let Some(runtime) = self.common.as_deref_mut()
        {
            runtime.buffer_event(Site::CommonUserSlot, Reason::ReceiptWait, *at, false);
            runtime.buffer_event(Site::CommonUserSlot, Reason::SocketWrite, *at, false);
        }
        if let Some(trace) = self
            .common
            .as_deref_mut()
            .and_then(|r| r.compact_arq_trace.as_mut())
        {
            trace.accepted(
                pending.scope.epoch.0,
                pending.sealed.number.0,
                at,
                accepted.as_ref().ok().copied(),
                receipt.boundary,
            );
        }
        let early_feedback = self.research_feedback_before_receipt(
            pending.scope,
            pending.sealed.number.0,
            receipt.accepted_at,
            physical_at,
            at,
        );
        let confirmation = self.confirm_common_output(
            pending.scope,
            at,
            physical_at,
            self.causal_time(receipt.accepted_at).ok(),
            pending.carrier,
            pending.fragment,
        );
        // Evaluate semantic eligibility once in its original precedence before
        // a last-unit receipt is allowed to release the independent Bridge.
        let eligibility = (|| {
            completed?;
            accepted?;
            confirmation?;
            early_feedback?;
            if late
                || receipt.accepted_at >= receipt.deadline
                || observed >= receipt.deadline
                || at >= pending.deadline
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "whole carrier write crossed original cap: epoch={} feedback={} deadline={} accepted={} observed={} late={}",
                        pending.scope.epoch.0,
                        pending.feedback,
                        pending.deadline,
                        physical_at,
                        at,
                        late
                    ),
                ));
            }
            self.check_expiry(at)
        })();
        #[cfg(unix)]
        let rejected = eligibility.as_ref().err().map(io::Error::kind).or_else(|| {
            matches!(&eligibility, Ok(false)).then(|| proxy_stopped_kind(self.terminal))
        });
        // Preserve the real fact even after an earlier error, but latch that
        // error first so this call cannot publish successful flush/ordinal.
        #[cfg(unix)]
        let proxy_completion = (|| {
            if let Some(unit) = pending.proxy_record {
                let bridge = self
                    .common
                    .as_deref()
                    .and_then(|runtime| runtime.proxy_bridge.as_ref())
                    .ok_or_else(|| protocol("Common proxy physical receipt lost bridge"))?;
                if let Some(kind) = rejected {
                    bridge.reject_completion(kind)?;
                }
                bridge.complete_unit(unit, receipt.accepted_at, observed)?;
            }
            Ok::<(), io::Error>(())
        })();
        if !eligibility? {
            return Ok(false);
        }
        #[cfg(unix)]
        proxy_completion?;
        self.retry_common_feedback(at)?;
        Ok(true)
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
            .as_deref()
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
        let next = if pending.feedback || self.common_authenticated_data() {
            self.records.next_feedback_number()
        } else {
            self.records.next_number(Class::User)
        };
        if !self.scope_registered(scope) || next.0 <= sealed.number.0 {
            return Err(protocol(
                "retained Common wire lost its original security scope/number",
            ));
        }
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Common sealed output cap",
            ));
        }
        if !self.common_retry_attempt(now)? {
            return Ok(false);
        }
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("common sealed owner"))?;
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
                if let Some(sample) = runtime.wire_sample.take()
                    && let Some(metrics) = runtime.wire_metrics.as_mut()
                {
                    metrics.accepted(
                        sample,
                        bytes,
                        super::super::SendBoundary::SocketAccepted,
                        Some(cost),
                    );
                }
                let sampled = sample();
                let completed = sampled.as_ref().copied().unwrap_or(u64::MAX);
                if let Ok(at) = sampled.as_ref() {
                    runtime.buffer_event(Site::CommonUserSlot, Reason::SocketWrite, *at, false);
                }
                if let Some(trace) = self
                    .common
                    .as_deref_mut()
                    .and_then(|r| r.compact_arq_trace.as_mut())
                {
                    trace.accepted(
                        pending.scope.epoch.0,
                        pending.sealed.number.0,
                        completed,
                        sampled.as_ref().ok().copied(),
                        super::super::SendBoundary::SocketAccepted,
                    );
                }
                let confirmation = self.confirm_common_output(
                    pending.scope,
                    completed,
                    completed,
                    None,
                    pending.carrier,
                    pending.fragment,
                );
                let physical_time = sampled.as_ref().ok().copied();
                let eligibility = (|| {
                    sampled?;
                    confirmation?;
                    if completed >= pending.deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "whole Common write crossed its original cap",
                        ));
                    }
                    self.check_expiry(completed)
                })();
                #[cfg(unix)]
                let rejected = eligibility.as_ref().err().map(io::Error::kind).or_else(|| {
                    matches!(&eligibility, Ok(false)).then(|| proxy_stopped_kind(self.terminal))
                });
                #[cfg(unix)]
                let proxy_completion = (|| {
                    if let Some(unit) = pending.proxy_record {
                        let bridge = self
                            .common
                            .as_deref()
                            .and_then(|runtime| runtime.proxy_bridge.as_ref())
                            .ok_or_else(|| protocol("Common proxy physical receipt lost bridge"))?;
                        if let Some(kind) = rejected {
                            bridge.reject_completion(kind)?;
                        }
                        if let Some(physical_time) = physical_time {
                            let accepted = self
                                .origin
                                .checked_add(duration(physical_time))
                                .ok_or_else(exhausted)?;
                            bridge.complete_unit(unit, accepted, accepted)?;
                        }
                    }
                    Ok::<(), io::Error>(())
                })();
                if !eligibility? {
                    return Ok(false);
                }
                #[cfg(unix)]
                proxy_completion?;
                self.retry_common_feedback(completed)?;
                Ok(true)
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial Common UDP handoff",
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                runtime.buffer_event(Site::CommonUserSlot, Reason::SocketWrite, now, true);
                Ok(false)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::HostUnreachable
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::NetworkDown
                ) =>
            {
                // This attempt accepted no datagram. Keep the exact sealed
                // owner/token/debit; only genuine protected ingress resumes it.
                self.common_path_failure(now, error.kind())?;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
    pub(super) fn receive_common_user_at(
        &mut self,
        opened: record::Opened,
        received: u64,
        now: u64,
    ) -> io::Result<()> {
        let original = self
            .origin
            .checked_add(duration(received))
            .ok_or_else(exhausted)?;
        self.receive_common_user_observed(opened, received, now, original)
    }
    pub(super) fn receive_common_user_observed(
        &mut self,
        opened: record::Opened,
        received: u64,
        now: u64,
        original: Instant,
    ) -> io::Result<()> {
        // This method is reached only after the sole Records opener and route
        // check; short unkeyed data is deliberately outside authenticated traces.
        let trace_packet = if opened.authenticated {
            let owner::DataOwner::Common(state) = &self.owner;
            self.common
                .as_deref_mut()
                .and_then(|r| r.compact_arq_trace.as_mut())
                .and_then(|trace| {
                    let engine = state.engine(core::Epoch(opened.scope.epoch.0)).ok()?;
                    if engine.fragment_policy().is_some() {
                        return None;
                    }
                    let packet = trace.inspect(
                        engine
                            .configuration()
                            .descriptor()
                            .local(common_contract::mg_role(self.info.role)),
                        false,
                        &self.buffers.plain[..opened.bytes],
                    )?;
                    trace.input(
                        "input",
                        opened.scope.epoch.0,
                        opened.number.0,
                        now,
                        Some(received),
                        packet,
                        common::compact_arq_trace::Outcome::AuthenticatedInput,
                    );
                    Some(packet)
                })
        } else {
            None
        };
        self.retry_common_feedback(now)?;
        self.retry_common_connection_input(now)?;
        if self.receive_common_fragment_at(opened, received, now, original)? {
            return Ok(());
        }
        if self.common.as_deref().is_some_and(|runtime| {
            runtime
                .pending_feedback
                .is_some_and(|p| p.physical_dependency.is_none())
        }) && !self.connection_scope(opened.scope)?
        {
            // Only one exact input is retained. Continue Control/Liveness reads;
            // additional lossy User packets cannot overwrite the retained ACK.
            if let Some(packet) = trace_packet
                && let Some(trace) = self
                    .common
                    .as_deref_mut()
                    .and_then(|r| r.compact_arq_trace.as_mut())
            {
                trace.input(
                    "blocked",
                    opened.scope.epoch.0,
                    opened.number.0,
                    now,
                    Some(received),
                    packet,
                    common::compact_arq_trace::Outcome::RetainedInputBlocked,
                );
            }
            self.counters.native_backpressure_drops =
                self.counters.native_backpressure_drops.saturating_add(1);
            return Ok(());
        }
        let epoch = core::Epoch(opened.scope.epoch.0);
        let state = self.common_state()?;
        let Some(reader) = state.peer().reader(epoch) else {
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(());
        };
        if common_actions::record_scope(reader.scope) != opened.scope
            || !self.scope_registered(opened.scope)
        {
            return Err(protocol("common authenticated reader scope differs"));
        }
        let local = reader
            .config
            .descriptor()
            .local(common_contract::mg_role(self.info.role));
        let body = &self.buffers.plain[..opened.bytes];
        let kind = state.engine(epoch)?.inspect_peer(body).map_err(protocol)?;
        let staged_reader = reader.disposition == transaction::ReadDisposition::Staged;
        let deferred_decode = matches!(
            local.receive().profile(),
            configuration::DirectionProfile::Rolling { .. }
                | configuration::DirectionProfile::Research { .. }
        );
        let queued_rolling_input = self.config.rolling_ingress.is_some()
            && deferred_decode
            && kind != engine::EmissionKind::Feedback;
        let width = usize::from(local.receive().channels());
        if kind == engine::EmissionKind::Feedback
            && self.retain_research_feedback(opened, received, now, original)?
        {
            return Ok(());
        }
        if kind == engine::EmissionKind::Feedback
            && self
                .common
                .as_deref()
                .is_some_and(|runtime| runtime.pending_feedback.is_some())
        {
            if let Some(packet) = trace_packet
                && let Some(trace) = self
                    .common
                    .as_deref_mut()
                    .and_then(|r| r.compact_arq_trace.as_mut())
            {
                trace.input(
                    "blocked",
                    opened.scope.epoch.0,
                    opened.number.0,
                    now,
                    Some(received),
                    packet,
                    common::compact_arq_trace::Outcome::RetainedInputBlocked,
                );
            }
            self.counters.native_backpressure_drops =
                self.counters.native_backpressure_drops.saturating_add(1);
            return Ok(());
        }
        if staged_reader && kind != engine::EmissionKind::Feedback {
            return Err(protocol(
                "staged common generation cannot admit native-producing data",
            ));
        }
        // Rolling inputs only stage decoder work. Its later receive step arms
        // native scans after admitting records or advancing their ordered head.
        if !deferred_decode {
            self.common
                .as_deref_mut()
                .ok_or_else(|| protocol("common scan contract"))?
                .native_work[(epoch.0 % 2) as usize] = width;
        }
        let raw_connection = kind == engine::EmissionKind::UnreliableNative;
        let mut original_deadline = if raw_connection {
            self.raw_connection_deadline(opened.scope, received)?
        } else {
            self.lease
        };
        if raw_connection && now >= original_deadline {
            return self.retain_common_connection_input(opened, received, now, original_deadline);
        }
        if queued_rolling_input
            && let Some(cap) = self
                .common_state()?
                .operation_deadline()
                .into_iter()
                .chain(
                    self.common
                        .as_deref()
                        .and_then(|runtime| runtime.outcome)
                        .map(common_actions::outcome_deadline),
                )
                .min()
        {
            original_deadline =
                original_deadline.min(u64::try_from(cap.as_micros()).map_err(invalid)?);
        }
        let owner::DataOwner::Common(state) = &mut self.owner;
        let mut entry = state.entry(epoch)?;
        let accepted = if queued_rolling_input || raw_connection {
            entry.accept_authenticated_until(
                engine::Tick(received),
                engine::Tick(now),
                engine::Tick(original_deadline),
                opened.number.0,
                kind,
                &mut self.buffers.plain[..opened.bytes],
            )
        } else {
            // Feedback and every unchanged family retain the existing service
            // boundary; source-queue custody cannot monopolize reverse feedback.
            entry.accept_authenticated_at(
                engine::Tick(received),
                engine::Tick(now),
                opened.number.0,
                kind,
                &mut self.buffers.plain[..opened.bytes],
            )
        };
        if let Some(packet) = trace_packet
            && let Some(trace) = self
                .common
                .as_deref_mut()
                .and_then(|r| r.compact_arq_trace.as_mut())
        {
            let outcome = match &accepted {
                Ok(()) => common::compact_arq_trace::Outcome::Applied,
                Err(error) => common::compact_arq_trace::Outcome::Rejected(*error),
            };
            trace.input(
                "apply",
                opened.scope.epoch.0,
                opened.number.0,
                now,
                Some(received),
                packet,
                outcome,
            );
        }
        match accepted {
            Ok(()) => Ok(()),
            Err(error) if common_connections::feedback_awaiting_physical(&error) => {
                self.retain_common_feedback_at(opened, kind, received, now)
            }
            Err(record_bank::Error::Engine(engine::Error::Connections(
                l2tunnel::connection_records::Error::UnreliableBusy,
            ))) => self.retain_common_connection_input(opened, received, now, original_deadline),
            Err(record_bank::Error::Engine(engine::Error::Connections(error)))
                if error.is_backpressure() =>
            {
                if let Some(runtime) = self.common.as_deref_mut() {
                    buffer_metrics::authenticated_input_dropped(
                        runtime,
                        now,
                        kind,
                        engine::Error::Connections(error),
                    );
                }
                self.counters.native_backpressure_drops =
                    self.counters.native_backpressure_drops.saturating_add(1);
                Ok(())
            }
            Err(record_bank::Error::Engine(engine::Error::Aligned(error)))
                if error.is_backpressure() =>
            {
                if let Some(runtime) = self.common.as_deref_mut() {
                    buffer_metrics::authenticated_input_dropped(
                        runtime,
                        now,
                        kind,
                        engine::Error::Aligned(error),
                    );
                }
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
        Ok(self.wake_common_with_custody(now, false, false)?.at)
    }
    pub(super) fn wake_common_with_custody(
        &self,
        now: u64,
        held_user: bool,
        held_control: bool,
    ) -> io::Result<SelectedWake> {
        let mut wake = self.lease;
        let mut work_ready = false;
        if let Some(state) = self
            .common
            .as_deref()
            .and_then(|r| r.reuse_controller())
            .filter(|r| r.active())
        {
            wake = wake
                .min(state.deadline())
                .min(add(now, self.config.work.receive_interval)?);
        }
        #[cfg(unix)]
        if let Some(cap) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.proxy_bridge.as_ref())
            .map(|bridge| bridge.retirement_deadline())
            .transpose()?
            .flatten()
        {
            wake = wake.min(clock(self.origin, cap)?);
        }
        if let Some(input) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.connection_input.as_ref())
            && let Some(deadline) = input.snapshot().deadline_micros
        {
            wake = wake
                .min(deadline)
                .min(add(now, self.config.work.receive_interval)?);
        }
        if let Some(pending) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.pending_ingress)
        {
            wake = wake
                .min(pending.deadline)
                .min(add(now, self.config.work.receive_interval)?);
        }
        for epoch in self.common_epochs().into_iter().flatten() {
            if let Some(at) = self
                .common_state()?
                .engine(epoch)?
                .ingress_wake_at(engine::Tick(now), self.config.work.receive_interval)
                .map_err(protocol)?
            {
                wake = wake.min(at.0);
            }
        }
        if let Some(pending) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.pending_feedback)
        {
            wake = wake.min(pending.deadline);
        }
        if !held_user
            && let Some(pending) = self
                .common
                .as_deref()
                .and_then(|runtime| runtime.sealed.as_ref())
        {
            let retry = self
                .common
                .as_deref()
                .filter(|runtime| runtime.path.unavailable)
                .and_then(|runtime| runtime.path.retry_at_micros)
                .unwrap_or(now);
            wake = wake.min(retry).min(pending.deadline);
        }
        if let Some(pending) = self.common.as_deref().and_then(|r| r.unsealed.as_ref()) {
            wake = wake
                .min(pending.deadline)
                .min(add(now, self.config.work.receive_interval)?);
        }
        if let Some(pending) = self.common.as_deref().and_then(|r| r.raw_control.as_ref()) {
            wake = wake.min(clock(self.origin, pending.deadline)?).min(
                self.bucket
                    .ready_at(pending.wire_bytes)?
                    .max(add(now, self.config.work.receive_interval)?),
            );
        }
        let held_control = held_control
            || self
                .common
                .as_deref()
                .is_some_and(|r| r.raw_control.is_some());
        // A retained retry already owns the only User wire slot. Do not wake
        // on another data/feedback poll while that exact slot waits its cadence.
        let held_user = held_user
            || self.common.as_deref().is_some_and(|runtime| {
                runtime.unsealed.is_some() || (runtime.path.unavailable && runtime.sealed.is_some())
            });
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
        if self.challenge.is_none() && !self.proxy_liveness_quiesced()? {
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
                work_ready = true;
                wake = wake.min(now);
            }
            if held_user {
                // Soft output opportunities cannot progress while the sole
                // carrier slot is held. Original retention caps still apply.
                if let Some(at) = engine.expiry_deadline().map_err(protocol)? {
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
                .as_deref()
                .ok_or_else(|| protocol("common wake contract"))?
                .contract
                .geometry()
                .forward_overhead_bytes;
            if engine.pending_fragment_group().is_some() {
                // Its complete shared allowance was paid at reservation. Only
                // another physical fragment and its original cap remain.
                wake = wake.min(now);
                if let Some(at) = engine.expiry_deadline().map_err(protocol)? {
                    wake = wake.min(at.0);
                }
                continue;
            }
            // Drain excludes user-data custody, not later duplicate-triggered
            // feedback. Every retained reader keeps its actual small ACK wake.
            if let Some((at, bytes)) = engine.feedback_opportunity().map_err(protocol)? {
                let feedback_overhead = self
                    .common
                    .as_deref()
                    .ok_or_else(|| protocol("common feedback wake contract"))?
                    .contract
                    .feedback_overhead_bytes()?;
                let cost = self.common_fragment_wire_cost(epoch, bytes)?.map_or_else(
                    || bytes.checked_add(feedback_overhead).ok_or_else(exhausted),
                    Ok,
                )?;
                let required = cost.checked_add(self.reserve).ok_or_else(exhausted)?;
                wake = wake.min(at.0.max(self.bucket.ready_at(required)?));
            }
            // Physical promotion follows the complete old-generation barrier.
            // Staged and post-promotion old readers owe no new DATA output;
            // their original maximum must not enlarge the new active burst.
            if epoch.0 != self.source_scope.epoch.0 || engine.drained().map_err(protocol)? {
                continue;
            }
            let logical = common_contract::maximum_body(local.send(), local.receive())?;
            let cost = self
                .common_fragment_wire_cost(epoch, logical)?
                .map_or_else(|| logical.checked_add(overhead).ok_or_else(exhausted), Ok)?;
            let required = cost.checked_add(self.reserve).ok_or_else(exhausted)?;
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
        // Keep the idle anti-spin floor, but do not send runnable bounded
        // protocol computation through the timer wheel on every work turn.
        Ok(SelectedWake {
            at: if work_ready {
                instant
            } else {
                instant.max(floor)
            },
            work_ready,
        })
    }
}
impl Driver {
    fn retain_common_feedback_at(
        &mut self,
        opened: record::Opened,
        kind: engine::EmissionKind,
        received: u64,
        observed: u64,
    ) -> io::Result<()> {
        if kind != engine::EmissionKind::Feedback {
            return Err(protocol("physical feedback pressure on non-feedback body"));
        }
        let runtime = self
            .common
            .as_deref()
            .ok_or_else(|| protocol("common feedback owner"))?;
        let (scope, carrier, deadline) = if let Some(output) = runtime.sealed.as_ref() {
            (output.scope, output.carrier.as_ref(), output.deadline)
        } else if let Some(output) = runtime.unsealed.as_ref() {
            (output.scope, output.carrier.as_ref(), output.deadline)
        } else {
            return Err(protocol("feedback lost physical dependency"));
        };
        if scope != opened.scope
            || carrier.is_none_or(|token| {
                token.emission().kind != engine::EmissionKind::Source(engine::SourceForm::DirectArq)
            })
            || runtime.pending_feedback.is_some()
        {
            return Err(protocol("feedback physical dependency differs"));
        }
        let mut deadline = deadline.min(self.lease);
        if let Some(cap) = self
            .common_state()?
            .operation_deadline()
            .into_iter()
            .chain(runtime.outcome.map(common_actions::outcome_deadline))
            .min()
        {
            deadline = deadline.min(u64::try_from(cap.as_micros()).map_err(invalid)?);
        }
        if received > observed || observed >= deadline {
            self.terminal = Some(StopReason::PolicyTimeout);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original retained feedback cap",
            ));
        }
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("common feedback owner"))?;
        runtime
            .feedback_input
            .get_mut(..opened.bytes)
            .ok_or_else(|| protocol("retained feedback payload capacity"))?
            .copy_from_slice(
                self.buffers
                    .plain
                    .get(..opened.bytes)
                    .ok_or_else(|| protocol("authenticated feedback plaintext length"))?,
            );
        runtime.pending_feedback = Some(common::PendingFeedback {
            scope: opened.scope,
            number: opened.number.0,
            bytes: opened.bytes,
            received,
            deadline,
            encoding: common_fragments::FeedbackEncoding::Record,
            physical_dependency: None,
            physical_arrival: None,
        });
        runtime.observation_dirty = true;
        Ok(())
    }

    pub(super) fn retry_common_feedback(&mut self, now: u64) -> io::Result<bool> {
        let Some(pending) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.pending_feedback)
        else {
            return Ok(true);
        };
        if let Some(dependency) = pending.physical_dependency
            && let Some(output) = self.common.as_deref().and_then(|r| r.sealed.as_ref())
        {
            if output.scope != pending.scope || output.sealed.number.0 != dependency {
                return Err(protocol("Research feedback physical dependency changed"));
            }
            return Ok(false);
        }
        if let Some(dependency) = pending.physical_dependency
            && let Some(output) = self.common.as_deref().and_then(|r| r.unsealed.as_ref())
        {
            if output.scope != pending.scope || output.number.0 != dependency {
                return Err(protocol(
                    "Research feedback pending-body dependency changed",
                ));
            }
            return Ok(false);
        }
        if !self.check_expiry(now)? {
            return Ok(false);
        }
        if !self.scope_registered(pending.scope) {
            return Err(protocol(
                "retained feedback scope retired before completion",
            ));
        }
        let epoch = core::Epoch(pending.scope.epoch.0);
        let state = self.common_state()?;
        let reader = state
            .peer()
            .reader(epoch)
            .ok_or_else(|| protocol("retained feedback reader missing"))?;
        if common_actions::record_scope(reader.scope) != pending.scope {
            return Err(protocol("retained feedback reader changed"));
        }
        let order = pending
            .physical_arrival
            .map(|at| self.causal_time(at))
            .transpose()?;
        let owner::DataOwner::Common(state) = &mut self.owner;
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("retained feedback runtime missing"))?;
        let bytes = runtime
            .feedback_input
            .get_mut(..pending.bytes)
            .ok_or_else(|| protocol("retained feedback length changed"))?;
        let trace_packet = if pending.encoding == common_fragments::FeedbackEncoding::Record {
            runtime.compact_arq_trace.as_mut().and_then(|trace| {
                let engine = state.engine(epoch).ok()?;
                if engine.fragment_policy().is_some() {
                    return None;
                }
                trace.inspect(
                    engine
                        .configuration()
                        .descriptor()
                        .local(common_contract::mg_role(self.info.role)),
                    false,
                    bytes,
                )
            })
        } else {
            None
        };
        let result = match pending.encoding {
            common_fragments::FeedbackEncoding::Record => {
                state.entry(epoch)?.accept_authenticated_at(
                    engine::Tick(pending.received),
                    engine::Tick(now),
                    pending.number,
                    engine::EmissionKind::Feedback,
                    bytes,
                )
            }
            common_fragments::FeedbackEncoding::Fragment => {
                let mut entry = state.entry(epoch)?;
                match order {
                    Some(order) => entry.accept_fragment_authenticated_ordered_until(
                        engine::Tick(pending.received),
                        engine::Tick(now),
                        engine::Tick(pending.deadline),
                        pending.number,
                        order,
                        bytes,
                    ),
                    None => entry.accept_fragment_authenticated_until(
                        engine::Tick(pending.received),
                        engine::Tick(now),
                        engine::Tick(pending.deadline),
                        pending.number,
                        bytes,
                    ),
                }
                .map(|_| ())
            }
        };
        if let Some(packet) = trace_packet
            && let Some(trace) = runtime.compact_arq_trace.as_mut()
        {
            let outcome = match &result {
                Ok(()) => common::compact_arq_trace::Outcome::Applied,
                Err(error) => common::compact_arq_trace::Outcome::Rejected(*error),
            };
            trace.input(
                "retry",
                pending.scope.epoch.0,
                pending.number,
                now,
                Some(pending.received),
                packet,
                outcome,
            );
        }
        match result {
            Ok(()) => {
                runtime.pending_feedback = None;
                runtime.observation_dirty = true;
                Ok(true)
            }
            Err(record_bank::Error::Engine(engine::Error::FragmentBusy))
                if pending.encoding == common_fragments::FeedbackEncoding::Fragment =>
            {
                Ok(false)
            }
            Err(error) if common_connections::feedback_awaiting_physical(&error) => Ok(false),
            Err(error) => Err(protocol(error)),
        }
    }
}

// A stopped Driver cannot grant a successful Bridge completion. This projection
// preserves the Driver's actual stop reason; it never changes that reason or cap.
#[cfg(unix)]
fn proxy_stopped_kind(reason: Option<StopReason>) -> io::ErrorKind {
    match reason {
        Some(StopReason::Io(kind)) => kind,
        Some(
            StopReason::LeaseExpired
            | StopReason::PeerTimeout
            | StopReason::NativeStall
            | StopReason::PolicyTimeout,
        ) => io::ErrorKind::TimedOut,
        Some(StopReason::Protocol) => io::ErrorKind::InvalidData,
        Some(StopReason::CounterExhausted) => io::ErrorKind::Other,
        Some(StopReason::Cancelled | StopReason::ProxyRetired) | None => io::ErrorKind::Interrupted,
    }
}

//! Optional Benchmark ingress on the existing sole Driver and its actual read slab.
use super::*;
use crate::initialization_timing::{Stage, Timing};
use l2tunnel::{record_bank, record_engine as engine};
use l2tunnel_pipeline::ack_coalescing as ack;

impl Driver {
    /// A send can move a MUX head after this turn has already tried the
    /// retained native input. Reopen reads before the next readiness selection
    /// when the issuing generation has actually made room.
    pub(super) fn send_and_retry_native_ingress<R: raw_carrier::RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        input: &[u8],
        now: u64,
        instant: Instant,
        mut sample: impl FnMut() -> Instant,
    ) -> io::Result<()> {
        let before = if let Some(p) = self.common.as_deref().and_then(|r| r.pending_ingress) {
            Some((
                p,
                self.common_state()?.engine(p.epoch)?.statistics().admitted,
            ))
        } else {
            None
        };
        self.send_selected_io_sampled(socket, now, instant, &mut sample)?;
        if let Some((p, prior)) = before
            && self.terminal.is_none()
            && self.common.as_deref().and_then(|r| r.pending_ingress) == Some(p)
            && self.common_state()?.engine(p.epoch)?.statistics().admitted > prior
        {
            let at = clock(self.origin, sample())?;
            if self.check_expiry(at)? {
                self.retry_common_ingress(at, input)?;
            }
        }
        Ok(())
    }

    pub(super) fn service_common_protocol_stages(
        &mut self,
        mut now: u64,
        input: &mut [u8],
        timing: &mut Timing,
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<u64> {
        if self.next_held_ack_service().is_some() {
            now = sample()?;
        }
        timing.measure_result(Stage::CommonHeldIngress, || {
            self.service_common_ingress(now, input)
        })?;
        let mut run = |stage, operation: fn(&mut Self, u64) -> io::Result<()>| -> io::Result<()> {
            self.refresh_held_acks(&mut now, timing, &mut sample)?;
            if self.terminal.is_none() {
                timing.measure_result(stage, || operation(self, now))?;
            }
            Ok(())
        };
        run(Stage::CommonNativeCollection, Self::collect_native)?;
        run(Stage::CommonTransactionProgress, Self::progress)?;
        self.refresh_held_acks(&mut now, timing, &mut sample)?;
        if self.terminal.is_none() {
            now = timing.measure_result(Stage::CommonRollingComputation, || {
                self.service_common_rolling_sampled(now, &mut sample)
            })?;
        }
        self.refresh_held_acks(&mut now, timing, &mut sample)?;
        Ok(now)
    }

    pub(super) fn next_held_ack_service(&self) -> Option<u64> {
        self.common.as_deref()?.next_ack_service
    }

    fn refresh_held_acks(
        &mut self,
        now: &mut u64,
        timing: &mut Timing,
        sample: &mut impl FnMut() -> io::Result<u64>,
    ) -> io::Result<()> {
        if self.terminal.is_none()
            && let Some(due) = self.next_held_ack_service()
        {
            *now = sample()?;
            if *now >= due {
                timing.measure_result(Stage::CommonHeldIngress, || self.service_due_acks(*now))?;
            }
        }
        Ok(())
    }

    /// One bounded pass per live generation per loop turn; never a second actor.
    pub(super) fn service_common_ingress(&mut self, now: u64, input: &mut [u8]) -> io::Result<()> {
        let Some(runtime) = self.common.as_deref() else {
            return Ok(());
        };
        // The plain path has no held ACKs but can retain one refused original.
        if self.config.ack_coalescing.is_none() && runtime.pending_ingress.is_none() {
            return Ok(());
        }
        if !self.check_expiry(now)? {
            return Ok(());
        }
        if self.config.ack_coalescing.is_some() {
            self.service_held_acks(now)?;
        }
        self.retry_common_ingress(now, input)?;
        Ok(())
    }
    /// Honor the ACK hold interval even while carrier or native I/O is draining a batch.
    pub(super) fn service_due_acks(&mut self, now: u64) -> io::Result<()> {
        if self.next_held_ack_service().is_some_and(|at| now >= at) && self.check_expiry(now)? {
            self.service_held_acks(now)?;
        }
        Ok(())
    }
    fn service_held_acks(&mut self, now: u64) -> io::Result<()> {
        let draining = !self.common_state()?.can_admit_data()
            || self
                .common
                .as_deref()
                .and_then(|r| r.reuse_controller())
                .is_some_and(super::common_reuse::Controller::active);
        let work = self.config.work.native_read_batch;
        let mut next = None;
        let cadence = self.config.work.receive_interval;
        for epoch in self.common_epochs().into_iter().flatten() {
            match self.common_state_mut()?.entry(epoch)?.service_ingress(
                engine::Tick(now),
                draining,
                work,
            ) {
                Ok(_) => {}
                Err(record_bank::Error::Engine(engine::Error::Ingress(ack::Error::Expired))) => {
                    self.terminal = Some(StopReason::NativeStall);
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "original held ACK ingress deadline",
                    ));
                }
                Err(error) => return Err(protocol(error)),
            }
            if let Some(at) = self
                .common_state()?
                .engine(epoch)?
                .ingress_wake_at(engine::Tick(now), cadence)
                .map_err(protocol)?
            {
                next = Some(next.map_or(at.0, |other: u64| other.min(at.0)));
            }
        }
        if let Some(runtime) = self.common.as_deref_mut() {
            runtime.next_ack_service = next;
        }
        Ok(())
    }
    /// Do not read a second packet until the issuing generation consumes this one.
    pub(super) fn read_common_coalesced<D: NativeDevice>(
        &mut self,
        ready: &mut NativeGuard<'_, D>,
        output: &mut [u8],
        mut sample: impl FnMut() -> io::Result<u64>,
    ) -> io::Result<bool> {
        let before = sample()?;
        self.progress_common(before)?;
        if !self.check_expiry(before)? || !self.can_admit_common_native()? {
            return Ok(false);
        }
        let epoch = core::Epoch(self.source_scope.epoch.0);
        let generation = self.common_state_mut()?.entry(epoch)?.generation();
        let maximum = self
            .common_state()?
            .engine(epoch)?
            .configuration()
            .descriptor()
            .local(common_contract::mg_role(self.info.role))
            .send()
            .max_native();
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
        let Some(bytes) = received? else {
            return Ok(false);
        };
        if bytes == 0 || bytes > maximum || bytes > output.len() {
            self.counters.native_oversize = self.counters.native_oversize.saturating_add(1);
            return Ok(true);
        }
        if self.reject_retired_connection_native(epoch, &output[..bytes])? {
            self.counters.rejected_packets = self.counters.rejected_packets.saturating_add(1);
            return Ok(true);
        }
        let deadline = add(before, self.config.native.stall_timeout)?.min(self.lease);
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("Common ingress owner missing"))?;
        if runtime.pending_ingress.is_some() {
            return Err(protocol("Common native read overwrote pending input"));
        }
        runtime.pending_ingress = Some(common::PendingIngress {
            generation,
            flow_byte_wait: None,
            epoch,
            bytes,
            received: before,
            deadline,
        });
        let now = sample()?;
        if let Some(trace) = &mut runtime.reverse_trace {
            trace.read(now, epoch.0, &output[..bytes]);
        }
        if !self.check_expiry(now)? {
            return Ok(false);
        }
        // A stopped admission gate cannot discard an already observed original.
        // Its exact old generation consumes it before Stage captures its fence.
        self.progress_common(now)?;
        self.retry_common_ingress(now, output)
    }
    fn retry_common_ingress(&mut self, now: u64, input: &[u8]) -> io::Result<bool> {
        let Some(pending) = self
            .common
            .as_deref()
            .and_then(|runtime| runtime.pending_ingress)
        else {
            return Ok(false);
        };
        if now >= pending.deadline {
            self.terminal = Some(StopReason::NativeStall);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original native ingress custody deadline",
            ));
        }
        let bytes = input
            .get(..pending.bytes)
            .ok_or_else(|| protocol("retained native ingress length"))?;
        let blocked = match pending.flow_byte_wait {
            Some(wait) => wait.still_blocked(self.common_state()?.engine(pending.epoch)?),
            None => false,
        };
        let mut entry = self.common_state_mut()?.entry(pending.epoch)?;
        if entry.generation() != pending.generation {
            return Err(protocol("native ingress issuing generation replaced"));
        }
        if blocked {
            return Ok(false);
        }
        match entry.ingest_borrowed_at(
            engine::Tick(pending.received),
            engine::Tick(now),
            bytes,
            engine::Tick(pending.deadline),
        ) {
            Ok(admission) => {
                if !matches!(admission, engine::IngressAdmission::Forwarded(_)) {
                    let policy = self
                        .config
                        .ack_coalescing
                        .ok_or_else(|| protocol("missing ACK policy"))?;
                    let at = add(pending.received, policy.interval)?.min(pending.deadline);
                    let runtime = self
                        .common
                        .as_deref_mut()
                        .ok_or_else(|| protocol("Common ingress owner missing"))?;
                    runtime.next_ack_service =
                        Some(runtime.next_ack_service.map_or(at, |old| old.min(at)));
                }
                self.common
                    .as_deref_mut()
                    .ok_or_else(|| protocol("Common ingress owner missing"))?
                    .pending_ingress = None;
                if let Some(runtime) = self.common.as_deref_mut() {
                    runtime.buffer_event(
                        crate::buffer_metrics::Site::NativeIngress,
                        crate::buffer_metrics::Reason::BufferCapacity,
                        now,
                        false,
                    );
                }
                self.counters.native_read = self.counters.native_read.saturating_add(1);
                Ok(true)
            }
            Err(record_bank::Error::Engine(engine::Error::Ingress(cause))) => {
                self.refuse_common_ingress(pending, bytes, now, cause)
            }
            // Without ACK coalescing the plain Pipeline path reports the same
            // finite admission refusals directly. They are backpressure on the
            // retained original, never a protocol failure of the session.
            Err(record_bank::Error::Engine(engine::Error::Pipeline(
                cause @ (l2tunnel_pipeline::PipelineError::Budget(_)
                | l2tunnel_pipeline::PipelineError::Flow(
                    l2tunnel_packet::FlowError::Capacity,
                )),
            ))) => self.refuse_common_ingress(pending, bytes, now, ack::Error::Pipeline(cause)),
            Err(error) => Err(protocol(error)),
        }
    }
    /// Retain one original the plain (non-coalescing) path already read and the
    /// Pipeline refused for a finite queue limit; any other refusal still fails.
    pub(super) fn retain_refused_native(
        &mut self,
        error: record_bank::Error,
        pending: common::PendingIngress,
        bytes: &[u8],
        now: u64,
    ) -> io::Result<bool> {
        use l2tunnel_pipeline::PipelineError;
        let cause = match error {
            record_bank::Error::Engine(engine::Error::Pipeline(
                cause @ (PipelineError::Budget(_)
                | PipelineError::Flow(l2tunnel_packet::FlowError::Capacity)),
            )) => ack::Error::Pipeline(cause),
            other => return Err(protocol(other)),
        };
        let runtime = self
            .common
            .as_deref_mut()
            .ok_or_else(|| protocol("Common ingress owner missing"))?;
        if runtime.pending_ingress.is_some() {
            return Err(protocol("Common native read overwrote pending input"));
        }
        runtime.pending_ingress = Some(pending);
        self.refuse_common_ingress(pending, bytes, now, cause)
    }
    /// Count one finite admission refusal and keep the original for retry.
    fn refuse_common_ingress(
        &mut self,
        pending: common::PendingIngress,
        bytes: &[u8],
        now: u64,
        cause: ack::Error,
    ) -> io::Result<bool> {
        use l2tunnel_pipeline::{Budget, PipelineError};
        let flow_byte_wait =
            if cause == ack::Error::Pipeline(PipelineError::Budget(Budget::FlowBytes)) {
                self.common_state()?
                    .engine(pending.epoch)?
                    .flow_byte_wait(bytes)
            } else {
                None
            };
        let stats = &mut self.performance.counters;
        let counter = match cause {
            ack::Error::Capacity => &mut stats.native_ingress_ack_history_refusals,
            ack::Error::Pipeline(PipelineError::Flow(l2tunnel_packet::FlowError::Capacity)) => {
                &mut stats.native_ingress_flow_table_refusals
            }
            ack::Error::Pipeline(PipelineError::Budget(limit)) => match limit {
                Budget::Bytes => &mut stats.native_ingress_shared_byte_refusals,
                Budget::Packets => &mut stats.native_ingress_shared_packet_refusals,
                Budget::FlowBytes => &mut stats.native_ingress_flow_byte_refusals,
                Budget::FlowPackets => &mut stats.native_ingress_flow_packet_refusals,
            },
            _ => {
                return Err(protocol(record_bank::Error::Engine(
                    engine::Error::Ingress(cause),
                )));
            }
        };
        *counter = counter.saturating_add(1);
        if let Some(runtime) = self.common.as_deref_mut() {
            if let Some(pending) = &mut runtime.pending_ingress {
                pending.flow_byte_wait = flow_byte_wait;
            }
            runtime.buffer_event(
                crate::buffer_metrics::Site::NativeIngress,
                crate::buffer_metrics::Reason::BufferCapacity,
                now,
                true,
            );
        }
        Ok(false)
    }
}

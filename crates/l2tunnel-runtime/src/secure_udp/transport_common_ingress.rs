//! Optional Benchmark ingress on the existing sole Driver and its actual read slab.
use super::*;
use l2tunnel::{record_bank, record_engine as engine};
use l2tunnel_pipeline::ack_coalescing as ack;

impl Driver {
    /// One bounded pass per live generation per loop turn; never a second actor.
    pub(super) fn service_common_ingress(&mut self, now: u64, input: &mut [u8]) -> io::Result<()> {
        if self.common.is_none() || self.config.ack_coalescing.is_none() {
            return Ok(());
        }
        if !self.check_expiry(now)? {
            return Ok(());
        }
        let draining = !self.common_state()?.can_admit_data()
            || self
                .common
                .as_deref()
                .and_then(|r| r.reuse_controller())
                .is_some_and(super::common_reuse::Controller::active);
        let work = self.config.work.native_read_batch;
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
        }
        self.retry_common_ingress(now, input)?;
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
            epoch,
            bytes,
            received: before,
            deadline,
        });
        let now = sample()?;
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
        let mut entry = self.common_state_mut()?.entry(pending.epoch)?;
        if entry.generation() != pending.generation {
            return Err(protocol("native ingress issuing generation replaced"));
        }
        match entry.ingest_borrowed_at(
            engine::Tick(pending.received),
            engine::Tick(now),
            bytes,
            engine::Tick(pending.deadline),
        ) {
            Ok(
                engine::IngressAdmission::Forwarded(_)
                | engine::IngressAdmission::Held
                | engine::IngressAdmission::Superseded,
            ) => {
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
            Err(record_bank::Error::Engine(engine::Error::Ingress(
                ack::Error::Capacity
                | ack::Error::Pipeline(
                    l2tunnel_pipeline::PipelineError::Budget(_)
                    | l2tunnel_pipeline::PipelineError::Flow(l2tunnel_packet::FlowError::Capacity),
                ),
            ))) => {
                if let Some(runtime) = self.common.as_deref_mut() {
                    runtime.buffer_event(
                        crate::buffer_metrics::Site::NativeIngress,
                        crate::buffer_metrics::Reason::BufferCapacity,
                        now,
                        true,
                    );
                }
                Ok(false)
            }
            Err(error) => Err(protocol(error)),
        }
    }
}

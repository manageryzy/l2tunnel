//! Actual singleton-buffer refusal intervals; no inference from queue occupancy.
use super::*;
use crate::buffer_metrics::{Class as MetricClass, Extent, Key, Lane, Occupancy, Reason, Site};

impl common::Runtime {
    pub(super) fn buffer_event(&mut self, site: Site, reason: Reason, now: u64, blocked: bool) {
        if let Some(metrics) = self.buffer_metrics.as_mut()
            && !metrics.is_finished()
        {
            let key = Key {
                site,
                lane: Lane::Shared,
                class: MetricClass::Shared,
            };
            let _ = if blocked {
                metrics.collector().blocked(key, reason, now)
            } else {
                metrics.collector().progress(key, reason, now)
            };
        }
    }
}

impl Driver {
    pub(super) fn sample_raw_buffers<R: super::raw_carrier::RawBacking>(
        &mut self,
        socket: &mut carrier::IoOwner<R>,
        now: Instant,
        force: bool,
    ) {
        let Some(runtime) = self.common.as_deref_mut() else {
            return;
        };
        let Some(observer) = runtime.buffer_metrics.as_mut() else {
            return;
        };
        let Some(at) = observer.elapsed_at(now) else {
            return;
        };
        if !force && at < runtime.next_raw_buffer_sample {
            return;
        }
        runtime.next_raw_buffer_sample = at.saturating_add(10_000);
        if let Some(raw) = socket.final_raw_mut() {
            crate::secure_udp::raw_buffer_metrics::observe(raw.buffer_snapshot(now), observer, now);
        }
    }

    pub(super) fn sample_common_buffers(&mut self, now: u64) {
        let Some(runtime) = self.common.as_deref_mut() else {
            return;
        };
        let Some(metrics) = runtime.buffer_metrics.as_mut() else {
            return;
        };
        // These are singleton runtime gauges. Internal protocol buffers retain
        // their own owner/channel identities and are not folded into these slots.
        let native = (self.native.bytes(), self.native.len());
        let user = runtime
            .sealed
            .as_ref()
            .map(|v| v.sealed.bytes)
            .or_else(|| runtime.unsealed.as_ref().map(|v| v.bytes));
        for (site, bytes, items, byte_cap, item_cap) in [
            (
                Site::NativeOutputQueue,
                native.0,
                native.1,
                Some(self.config.native.pending_bytes),
                self.config.native.pending_packets,
            ),
            (
                Site::NativeIngress,
                runtime.pending_ingress.map_or(0, |v| v.bytes),
                usize::from(runtime.pending_ingress.is_some()),
                None,
                1,
            ),
            (
                Site::CommonUserSlot,
                user.unwrap_or(0),
                usize::from(user.is_some()),
                Some(runtime.wire.len()),
                1,
            ),
            (
                Site::RawControlSlot,
                runtime.raw_control.as_ref().map_or(0, |v| v.bytes),
                usize::from(runtime.raw_control.is_some()),
                None,
                1,
            ),
            (
                Site::DeferredFeedback,
                runtime.pending_feedback.map_or(0, |v| v.bytes),
                usize::from(runtime.pending_feedback.is_some()),
                Some(runtime.feedback_input.len()),
                1,
            ),
        ] {
            let _ = metrics.collector().sample(
                Key {
                    site,
                    lane: Lane::Shared,
                    class: MetricClass::Shared,
                },
                now,
                Occupancy {
                    bytes: Some(Extent {
                        used: bytes as u64,
                        capacity: byte_cap.map(|v| v as u64),
                    }),
                    items: Some(Extent {
                        used: items as u64,
                        capacity: Some(item_cap as u64),
                    }),
                },
            );
        }
    }
    pub(super) fn finish_buffer_metrics(&mut self, now: u64) {
        self.sample_common_buffers(now);
        if let Some(metrics) = self
            .common
            .as_deref_mut()
            .and_then(|r| r.buffer_metrics.as_mut())
        {
            metrics.finish_at(now);
        }
    }
}

pub(super) fn admission_refused(
    runtime: &mut common::Runtime,
    now: u64,
    refusal: l2tunnel::record_engine::AdmissionRefusal,
) {
    use l2tunnel::record_engine::AdmissionBlock;
    let reason = match refusal.reason {
        AdmissionBlock::NativeDeliveryWindow => Reason::NativeCredit,
        AdmissionBlock::SwiftPackingQueue | AdmissionBlock::ConnectionUnreliableSlot => {
            Reason::BufferCapacity
        }
        AdmissionBlock::CodecStage => Reason::CodecStage,
        AdmissionBlock::ConnectionRetirement => Reason::Dependency,
    };
    if let Some(metrics) = runtime.buffer_metrics.as_mut() {
        // This counter aggregates actual channel refusals. Timing it would merge
        // independent owners and falsely clear one channel when another advances.
        let _ = metrics.collector().refused(
            Key {
                site: Site::PipelineAdmission,
                lane: Lane::Shared,
                class: MetricClass::User,
            },
            reason,
            now,
        );
    }
}

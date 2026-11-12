//! Opt-in bounded managed-path observation; no protocol state or packet logs.
//! Timings are elapsed nanoseconds of completed/cancelled attempts, including
//! asynchronous suspension. Concurrent stages overlap; synchronous codec timings
//! can include preemption and are not process CPU measurements. In-progress waits
//! enter cumulative timing when completed/cancelled. Counters/snapshots are
//! coalesced diagnostic observations, not atomic cross-task protocol fences.
use std::collections::BTreeMap;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

macro_rules! labels {
    ($kind:ident, $names:ident, $($variant:ident => $label:literal),+ $(,)?) => {
        #[derive(Clone, Copy)]
        pub(super) enum $kind { $($variant),+ }
        const $names: &[&str] = &[$($label),+];
    };
}
labels!(Counter, COUNTERS,
    DriverIterations => "driver_iterations", WakeIncoming => "wake_incoming",
    WakeLocal => "wake_local", WakeDataFlush => "wake_data_flush",
    WakeFeedbackFlush => "wake_feedback_flush", WakeTimer => "wake_timer",
    DeviceReadCalls => "device_read_calls", DeviceReadNone => "device_read_none",
    DeviceReadFrames => "device_read_frames", DeviceReadBytes => "device_read_bytes",
    DeviceWriteCalls => "device_write_calls", DeviceWriteBlocked => "device_write_would_block",
    DeviceWriteFrames => "device_write_frames", DeviceWriteBytes => "device_write_bytes",
    EncodeFrames => "codec_encode_frames", EncodeBytes => "codec_encode_bytes",
    DecodeFrames => "codec_decode_frames", DecodeBytes => "codec_decode_bytes",
    RecordsRead => "records_read", RecordBytesRead => "plaintext_record_bytes_read",
    RecordsFlushed => "records_flushed", RecordBytesFlushed => "plaintext_record_bytes_flushed",
    DataFlushed => "data_records_flushed", FeedbackFlushed => "feedback_records_flushed",
    ControlFlushed => "control_records_flushed", WriterWakeData => "writer_wake_data",
    WriterWakeFeedback => "writer_wake_feedback", WriterWakeControl => "writer_wake_control",
    CreditBlocked => "data_admission_credit_blocked", QueueFull => "data_admission_queue_full",
    AdmissionPaused => "data_admission_protocol_paused", DataAdmitted => "data_admitted_frames",
    FeedbackUpdates => "feedback_updates",
);
labels!(HighWater, HIGH_WATER,
    NativePending => "native_pending_records", Incoming => "incoming_queue_records",
    Outgoing => "outgoing_queue_records", Control => "control_queue_records",
    Unconfirmed => "unconfirmed_native_packets", Unflushed => "unflushed_data_records",
    RecordBytes => "plaintext_record_bytes", NativeBytes => "native_frame_bytes",
    LocalQueueLimit => "configured_local_queue_packets", DeliveryCreditLimit => "configured_delivery_credit_packets",
);
labels!(Value, VALUES,
    Enabled => "delivery_enabled", Target => "delivery_target_bytes",
    OutstandingBytes => "delivery_outstanding_bytes", OutstandingRecords => "delivery_outstanding_records",
    RetainedRecords => "delivery_retained_records", Rtt => "delivery_service_rtt_micros",
    RttFresh => "delivery_service_rtt_fresh", PendingBytes => "delivery_native_pending_bytes",
    StagedBytes => "delivery_staged_native_bytes",
    ReservedBytes => "delivery_reserved_bytes", ReservedRecords => "delivery_reserved_records",
    UnflushedBytes => "delivery_unflushed_bytes", UnflushedRecords => "delivery_unflushed_records",
    FlushedUnacknowledgedBytes => "delivery_flushed_unacknowledged_bytes",
    FlushedUnacknowledgedRecords => "delivery_flushed_unacknowledged_records",
    DeliveredAwaitingCallbackBytes => "delivery_delivered_awaiting_flush_callback_bytes",
    DeliveredAwaitingCallbackRecords => "delivery_delivered_awaiting_flush_callback_records",

);
labels!(Stage, STAGES,
    DriverWait => "driver_select_wait", WriterWait => "writer_select_wait",
    DeviceRead => "device_read", DeviceWrite => "device_write",
    CodecEncode => "codec_encode", CodecDecode => "codec_decode",
    OuterEncode => "outer_encode", OuterDecode => "outer_decode",
    RecordRead => "transport_record_read", IncomingQueue => "incoming_queue_send_wait",
    FramedWrite => "transport_framed_write",
    Flush => "transport_flush", CreditBlocked => "credit_blocked_elapsed",
);

/// Stage attempt elapsed time, including suspended I/O and cancellation.
/// Concurrent stages overlap; these values are not additive CPU utilization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProfileTiming {
    /// Completed or cancelled stage attempts observed.
    pub count: u64,
    /// Sum of attempt elapsed nanoseconds, saturating at u64::MAX.
    pub total_nanos: u64,
    /// Longest observed attempt in nanoseconds.
    pub max_nanos: u64,
}
/// Bounded coalesced cumulative facts from the original retained runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileSnapshot {
    /// Monotonic elapsed nanoseconds since profiling was enabled.
    pub elapsed_nanos: u64,
    /// Runtime returned or was cancelled; never a graceful-drain assertion.
    pub terminal: bool,
    /// Fixed label set of saturating counters; no peer bytes or identities.
    pub counters: BTreeMap<&'static str, u64>,
    /// Maximum observed bounded queue/record values plus explicit configured limits.
    pub high_water: BTreeMap<&'static str, u64>,
    /// Current fixed-label delivery observations; delivery_enabled=0 means legacy policy.
    /// Unflushed/flushed describe local TLS full-flush callbacks, never physical wire delivery.
    pub values: BTreeMap<&'static str, u64>,
    /// Fixed label set of stage attempt timings.
    pub timings: BTreeMap<&'static str, ProfileTiming>,
}
struct Timing {
    count: AtomicU64,
    total: AtomicU64,
    maximum: AtomicU64,
}
struct Inner {
    start: Instant,
    interval: u64,
    next: AtomicU64,
    counters: [AtomicU64; COUNTERS.len()],
    values: [AtomicU64; VALUES.len()],
    high: [AtomicU64; HIGH_WATER.len()],
    stages: [Timing; STAGES.len()],
    output: watch::Sender<Option<ProfileSnapshot>>,
}
/// One replaceable observation subscription. Dropping it cannot stop traffic.
#[derive(Clone)]
pub struct ProfileHandle(watch::Receiver<Option<ProfileSnapshot>>);
impl ProfileHandle {
    /// Latest cumulative observation; querying never advances protocol state.
    pub fn status(&self) -> Option<ProfileSnapshot> {
        self.0.borrow().clone()
    }
    /// Subscribe to the same single coalesced snapshot slot.
    pub fn subscribe(&self) -> watch::Receiver<Option<ProfileSnapshot>> {
        self.0.clone()
    }
}
/// Optional runtime-owned observer; no background task or extra packet queue.
#[derive(Clone)]
pub struct ProfileSink(Arc<Inner>);
/// Enable one bounded observer at 100ms..=60s cadence. Invalid values fail before I/O.
pub fn channel(interval: Duration) -> io::Result<(ProfileHandle, ProfileSink)> {
    if !(Duration::from_millis(100)..=Duration::from_secs(60)).contains(&interval)
        || !interval.subsec_nanos().is_multiple_of(1_000_000)
    {
        return Err(super::invalid(
            "managed profiling interval must be100..60000ms",
        ));
    }
    let interval = u64::try_from(interval.as_nanos()).map_err(io::Error::other)?;
    let (output, receive) = watch::channel(None);
    Ok((
        ProfileHandle(receive),
        ProfileSink(Arc::new(Inner {
            start: Instant::now(),
            interval,
            next: AtomicU64::new(interval),
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            values: std::array::from_fn(|_| AtomicU64::new(0)),
            high: std::array::from_fn(|_| AtomicU64::new(0)),
            stages: std::array::from_fn(|_| Timing {
                count: AtomicU64::new(0),
                total: AtomicU64::new(0),
                maximum: AtomicU64::new(0),
            }),
            output,
        })),
    ))
}
fn nanos(value: Duration) -> u64 {
    u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
}
fn add(cell: &AtomicU64, value: u64) {
    let _ = cell.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(value))
    });
}
pub(super) struct Span<'a> {
    sink: &'a ProfileSink,
    stage: Stage,
    start: Instant,
}
impl Drop for Span<'_> {
    fn drop(&mut self) {
        self.sink.duration(self.stage, self.start.elapsed());
    }
}
impl ProfileSink {
    pub(super) fn value(&self, key: Value, value: u64) {
        self.0.values[key as usize].store(value, Ordering::Relaxed);
    }
    pub(super) fn count(&self, key: Counter, value: u64) {
        add(&self.0.counters[key as usize], value);
    }
    pub(super) fn high(&self, key: HighWater, value: u64) {
        self.0.high[key as usize].fetch_max(value, Ordering::Relaxed);
    }
    pub(super) fn span(&self, stage: Stage) -> Span<'_> {
        Span {
            sink: self,
            stage,
            start: Instant::now(),
        }
    }
    pub(super) fn duration(&self, stage: Stage, elapsed: Duration) {
        let stage = &self.0.stages[stage as usize];
        let elapsed = nanos(elapsed);
        add(&stage.count, 1);
        add(&stage.total, elapsed);
        stage.maximum.fetch_max(elapsed, Ordering::Relaxed);
    }
    pub(super) fn publish(&self, terminal: bool) {
        let at = nanos(self.0.start.elapsed());
        if !terminal {
            let due = self.0.next.load(Ordering::Relaxed);
            if at < due
                || self
                    .0
                    .next
                    .compare_exchange(
                        due,
                        at.saturating_add(self.0.interval),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_err()
            {
                return;
            }
        }
        let snapshot = ProfileSnapshot {
            elapsed_nanos: at,
            terminal,
            counters: COUNTERS
                .iter()
                .enumerate()
                .map(|(i, label)| (*label, self.0.counters[i].load(Ordering::Relaxed)))
                .collect(),
            high_water: HIGH_WATER
                .iter()
                .enumerate()
                .map(|(i, label)| (*label, self.0.high[i].load(Ordering::Relaxed)))
                .collect(),
            values: VALUES
                .iter()
                .enumerate()
                .map(|(i, label)| (*label, self.0.values[i].load(Ordering::Relaxed)))
                .collect(),
            timings: STAGES
                .iter()
                .enumerate()
                .map(|(i, label)| {
                    let stage = &self.0.stages[i];
                    (
                        *label,
                        ProfileTiming {
                            count: stage.count.load(Ordering::Relaxed),
                            total_nanos: stage.total.load(Ordering::Relaxed),
                            max_nanos: stage.maximum.load(Ordering::Relaxed),
                        },
                    )
                })
                // Preserve old metric keys as unused zeros; never relabel old
                // prefix/body observations as the new combined framed write.
                .chain([
                    ("transport_prefix_write", ProfileTiming::default()),
                    ("transport_body_write", ProfileTiming::default()),
                ])
                .collect(),
        };
        self.0.output.send_replace(Some(snapshot));
    }
}
pub(super) struct Lifetime(pub Option<ProfileSink>);
impl Drop for Lifetime {
    fn drop(&mut self) {
        if let Some(sink) = &self.0 {
            sink.publish(true);
        }
    }
}

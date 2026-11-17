//! Sampled occupancy and separately observed exact staged-source admission waits.
use l2tunnel::{record_configuration::DirectionProfile, record_engine as engine};
use l2tunnel_aligned::staged_wait::{Snapshot as StagedWait, Totals as WaitTotals};
use l2tunnel_codec::diagnostics::{DuplexBuffers, Retention, SendBuffers};
use l2tunnel_management::Role;
use std::io::{self, Write};
use std::time::Duration;

#[path = "reliable_output_metrics.rs"]
mod reliable_output_metrics;
#[path = "rolling_wait_metrics.rs"]
mod rolling_wait_metrics;
use l2tunnel::rolling_records::waits::{Snapshot as RollingWait, Terminal as RollingTerminal};
use l2tunnel_reliable::diagnostics::Snapshot as ReliableOutput;

const SAMPLE_INTERVAL_US: u64 = 100_000;
const MAX_OWNERS: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) epoch: u64,
    pub(crate) configuration: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Owner {
    Endpoint,
    SwiftPacking,
    SwiftChannel {
        channel: usize,
        send: bool,
        receive: bool,
    },
    Connection {
        owner: u16,
        incarnation: u64,
    },
}
impl Owner {
    fn index(self) -> usize {
        match self {
            Self::Endpoint | Self::SwiftPacking => 0,
            Self::SwiftChannel { channel, .. } => channel + 1,
            Self::Connection { owner, .. } => usize::from(owner),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Gauge {
    samples: u64,
    used: Option<u64>,
    high_water: Option<u64>,
    capacity: Option<u64>,
}

const NAMES: [&str; 38] = [
    "codec_stage_items",
    "codec_stage_bytes",
    "codec_stage_remaining_bytes",
    "packing_source_items",
    "packing_source_bytes",
    "packing_units",
    "receiver_source_proof_items",
    "receiver_source_proof_bytes",
    "receiver_head_items",
    "receiver_head_bytes",
    "receiver_lookahead_items",
    "receiver_lookahead_bytes",
    "receiver_head_fragments",
    "receiver_lookahead_fragments",
    "receiver_pending_native_items",
    "receiver_pending_native_bytes",
    "arq_send_records",
    "arq_send_payload_bytes",
    "arq_receive_records",
    "arq_receive_payload_bytes",
    "reliable_building_packets",
    "reliable_building_bytes",
    "reliable_outbound_packets",
    "reliable_outbound_bytes",
    "reliable_restored_packets",
    "reliable_restored_bytes",
    "arq_transmission_history_entries",
    "reliable_fec_logical_reservation_bytes",
    "reliable_fec_live_generations",
    "reliable_fec_basis_rows",
    "reliable_fec_history_symbols",
    "reliable_fec_completed_generations",
    "reliable_fec_allocated_backing_bytes",
    "reliable_physical_main_packets",
    "reliable_physical_feedback_packets",
    "reliable_physical_main_bytes",
    "reliable_physical_feedback_bytes",
    "reliable_outbound_packet_bytes_maximum",
];

// Reuse the existing row storage; Swift channel pools have different meanings.
const SWIFT_NAMES: [&str; 11] = [
    "swift_sender_packing_bytes",
    "swift_sender_source_records",
    "swift_sender_source_payload_bytes",
    "swift_sender_retry_entries",
    "swift_sender_repairs_due",
    "swift_receiver_source_positions",
    "swift_receiver_known_sources",
    "swift_receiver_source_payload_bytes",
    "swift_receiver_equation_rows",
    "swift_receiver_equation_payload_bytes",
    "swift_receiver_stream_bytes",
];
const SWIFT_PACKING_NAMES: [&str; 1] = ["swift_shared_packing_bytes"];

#[derive(Clone, Copy)]
struct Row {
    owner: Owner,
    first: u64,
    last: u64,
    samples: u64,
    codec: bool,
    recovery: bool,
    active: bool,
    invalid: bool,
    overflow: bool,
    gauges: [Gauge; NAMES.len()],
    staged_admission: Option<StagedWait>,
}
impl Row {
    fn new(owner: Owner, now: u64) -> Self {
        Self {
            owner,
            first: now,
            last: now,
            samples: 0,
            codec: false,
            recovery: false,
            active: false,
            invalid: false,
            overflow: false,
            gauges: [Gauge::default(); NAMES.len()],
            staged_admission: None,
        }
    }
    fn observe(&mut self, now: u64) {
        if !self.active {
            increment(&mut self.samples, &mut self.overflow);
            self.last = now;
            self.active = true;
        }
    }
    fn gauge(&mut self, index: usize, used: Option<usize>, capacity: Option<usize>) {
        let Some(value) = self.gauges.get_mut(index) else {
            self.invalid = true;
            return;
        };
        let used = used.map(|v| v as u64);
        let capacity = capacity.map(|v| v as u64);
        self.invalid |= used
            .zip(capacity)
            .is_some_and(|(used, capacity)| used > capacity);
        increment(&mut value.samples, &mut self.overflow);
        value.used = used;
        value.capacity = capacity;
        if let Some(used) = used {
            value.high_water = Some(value.high_water.map_or(used, |old| old.max(used)));
        }
    }
    fn retention(&mut self, index: usize, value: Retention) {
        self.gauge(index, Some(value.items), Some(value.item_capacity));
        self.gauge(index + 1, Some(value.bytes), Some(value.byte_capacity));
    }
    fn codec(&mut self, buffers: DuplexBuffers) {
        self.codec = true;
        let stage = match buffers.send {
            SendBuffers::Aligned(stage) => stage,
            SendBuffers::Packed(packed) => {
                self.retention(3, packed.packing.source);
                self.gauge(
                    5,
                    Some(packed.packing.units),
                    Some(packed.packing.unit_capacity),
                );
                packed.stage
            }
        };
        self.retention(0, stage.stage);
        self.gauge(
            2,
            Some(stage.remaining_bytes),
            Some(stage.stage.byte_capacity),
        );
        let received = buffers.receive;
        self.retention(6, received.source_proofs);
        self.retention(8, received.heads);
        self.retention(10, received.lookahead);
        self.gauge(
            12,
            Some(received.head_fragments),
            Some(received.head_fragment_capacity),
        );
        self.gauge(
            13,
            Some(received.lookahead_fragments),
            Some(received.lookahead_fragment_capacity),
        );
        self.gauge(
            14,
            Some(usize::from(received.pending_native_bytes.is_some())),
            Some(1),
        );
        self.gauge(
            15,
            Some(received.pending_native_bytes.unwrap_or(0)),
            Some(received.native_capacity_bytes),
        );
    }
    fn swift(&mut self, buffers: l2tunnel_swift::diagnostics::ChannelBuffers) {
        self.codec = true;
        self.recovery = true;
        if let Some(send) = buffers.send {
            self.gauge(
                0,
                Some(send.packing_bytes),
                Some(send.packing_capacity_bytes),
            );
            self.gauge(
                1,
                Some(send.source_records),
                Some(send.source_capacity_records),
            );
            self.gauge(2, Some(send.source_bytes), Some(send.source_capacity_bytes));
            self.gauge(
                3,
                Some(send.retry_entries),
                Some(send.retry_capacity_entries),
            );
            // Earned repair work has no allocated payload capacity. It is neither
            // queued repair bytes nor evidence of an output wait.
            self.gauge(4, Some(send.repairs_due as usize), None);
        }
        if let Some(receive) = buffers.receive {
            self.gauge(
                5,
                Some(receive.source_positions),
                Some(receive.source_capacity_positions),
            );
            self.gauge(
                6,
                Some(receive.known_sources),
                Some(receive.source_capacity_positions),
            );
            self.gauge(
                7,
                Some(receive.source_bytes),
                Some(receive.source_capacity_bytes),
            );
            self.gauge(8, Some(receive.rows), Some(receive.row_capacity));
            self.gauge(9, Some(receive.row_bytes), Some(receive.row_capacity_bytes));
            self.gauge(
                10,
                Some(receive.stream_bytes),
                Some(receive.stream_capacity_bytes),
            );
        }
    }
    fn recovery(
        &mut self,
        storage: l2tunnel_reliable::Storage,
        send: Option<Bounds>,
        receive: Option<Bounds>,
    ) {
        self.recovery = true;
        self.gauge(
            16,
            Some(storage.arq.send_records),
            send.map(|v| v.send_records),
        );
        self.gauge(17, Some(storage.arq.send_bytes), send.map(|v| v.send_bytes));
        self.gauge(
            18,
            Some(storage.arq.receive_records),
            receive.map(|v| v.receive_records),
        );
        self.gauge(
            19,
            Some(storage.arq.receive_bytes),
            receive.map(|v| v.receive_bytes),
        );
        // Do not scan a potentially large ARQ history or infer use from its bound.
        self.gauge(26, None, send.and_then(|v| v.history));
        // Keep the established Compact R0/per-connection observations. Only
        // actual Block/Direct policies supply these additional operational caps.
        for (index, (used, capacity)) in [
            (
                storage.building_packets,
                storage.block.map(|v| v.building_packets_capacity),
            ),
            (storage.building_bytes, None),
            (
                storage.outbound_packets,
                storage.block.map(|v| v.outbound_packets_capacity),
            ),
            (storage.outbound_bytes, None),
            (
                storage.restored_packets,
                storage.block.map(|v| v.restored_packets_capacity),
            ),
            (
                storage.restored_bytes,
                storage.block.map(|v| v.restored_bytes_capacity),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            self.gauge(20 + index, Some(used), capacity);
        }
        if let Some(block) = storage.block {
            if let Some(fec) = block.decoder {
                self.gauge(
                    27,
                    Some(fec.logical_reservation_bytes),
                    Some(fec.logical_reservation_capacity),
                );
                self.gauge(28, Some(fec.generations), Some(fec.generations_capacity));
                self.gauge(29, Some(fec.basis_rows), Some(fec.basis_rows_capacity));
                self.gauge(
                    30,
                    Some(fec.history_symbols),
                    Some(fec.history_symbols_capacity),
                );
                self.gauge(
                    31,
                    Some(fec.completed_generations),
                    Some(fec.generations_capacity),
                );
                self.gauge(32, None, fec.allocated_capacity_bytes);
            }
            for lane in 0..2 {
                self.gauge(
                    33 + lane,
                    Some(block.physical_packets[lane]),
                    Some(block.physical_packets_capacity),
                );
                self.gauge(
                    35 + lane,
                    Some(block.physical_bytes[lane]),
                    Some(block.outbound_packet_bytes_maximum),
                );
            }
            self.gauge(37, None, Some(block.outbound_packet_bytes_maximum));
        }
    }
}

struct Epoch {
    identity: Option<Identity>,
    live: bool,
    first: u64,
    last: u64,
    samples: u64,
    rows: Vec<Option<Row>>,
    rolling: Vec<RollingWait>,
    reliable: Vec<ReliableOutput>,
}
impl Epoch {
    fn new(owners: usize) -> io::Result<Self> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(owners).map_err(io::Error::other)?;
        rows.resize(owners, None);
        Ok(Self {
            identity: None,
            live: false,
            first: 0,
            last: 0,
            samples: 0,
            rows,
            rolling: Vec::new(),
            reliable: Vec::new(),
        })
    }
}

pub(crate) struct ProtocolBuffers {
    epochs: Vec<Epoch>,
    role: Role,
    last: Option<u64>,
    identity_errors: u64,
    clock_regressions: u64,
    omitted_epochs: u64,
    omitted_owners: u64,
    unsupported_codec_samples: u64,
    staged_terminal_unavailable: u64,
    overflow: bool,
}
impl ProtocolBuffers {
    pub(crate) fn new(owners: usize, role: Role) -> io::Result<Self> {
        if !(1..=MAX_OWNERS).contains(&owners) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "protocol buffer owner bound",
            ));
        }
        let mut epochs = Vec::new();
        epochs.try_reserve_exact(2).map_err(io::Error::other)?;
        for _ in 0..2 {
            epochs.push(Epoch::new(owners)?);
        }
        Ok(Self {
            epochs,
            role,
            last: None,
            identity_errors: 0,
            clock_regressions: 0,
            omitted_epochs: 0,
            omitted_owners: 0,
            unsupported_codec_samples: 0,
            staged_terminal_unavailable: 0,
            overflow: false,
        })
    }
    pub(crate) fn configure_rolling_waits(&mut self) -> io::Result<()> {
        for epoch in &mut self.epochs {
            if epoch.rolling.capacity() != 0 {
                return Err(io::Error::other("rolling wait observer already configured"));
            }
            epoch
                .rolling
                .try_reserve_exact(1)
                .map_err(io::Error::other)?;
            if epoch.rolling.capacity() != 1 {
                return Err(io::Error::other("rolling wait observer capacity differs"));
            }
        }
        Ok(())
    }
    pub(crate) fn configure_reliable_output(&mut self) -> io::Result<()> {
        for epoch in &mut self.epochs {
            if epoch.reliable.capacity() != 0 {
                return Err(io::Error::other(
                    "reliable output observer already configured",
                ));
            }
            epoch
                .reliable
                .try_reserve_exact(1)
                .map_err(io::Error::other)?;
            if epoch.reliable.capacity() != 1 {
                return Err(io::Error::other(
                    "reliable output observer capacity differs",
                ));
            }
        }
        Ok(())
    }
    pub(crate) fn heap_bytes(&self) -> usize {
        self.epochs.capacity() * std::mem::size_of::<Epoch>()
            + self
                .epochs
                .iter()
                .map(|v| {
                    v.rows.capacity() * std::mem::size_of::<Option<Row>>()
                        + v.rolling.capacity() * std::mem::size_of::<RollingWait>()
                        + v.reliable.capacity() * std::mem::size_of::<ReliableOutput>()
                })
                .sum::<usize>()
    }
    pub(crate) fn identity_unavailable(&mut self) {
        increment(&mut self.identity_errors, &mut self.overflow);
    }
    pub(crate) fn defer_sample(&mut self, now: u64) {
        // A failed identity observation must not retire an unknown live epoch.
        // Bound retries by the same cadence without relabeling old samples.
        if self.last.is_none_or(|last| now >= last) {
            self.last = Some(now);
        } else {
            increment(&mut self.clock_regressions, &mut self.overflow);
        }
    }
    pub(crate) fn due(&self, now: u64, force: bool) -> bool {
        force
            || self
                .last
                .is_none_or(|at| now < at || now.saturating_sub(at) >= SAMPLE_INTERVAL_US)
    }
    pub(crate) fn begin(&mut self, now: u64, live: [Option<Identity>; 2]) -> bool {
        if self.last.is_some_and(|last| now < last) {
            increment(&mut self.clock_regressions, &mut self.overflow);
            return false;
        }
        if live[0].is_some() && live[0] == live[1] {
            self.identity_unavailable();
            return false;
        }
        self.last = Some(now);
        for epoch in &mut self.epochs {
            epoch.live = epoch
                .identity
                .is_some_and(|identity| live.contains(&Some(identity)));
            for row in epoch.rows.iter_mut().flatten() {
                row.active = false;
            }
        }
        for identity in live.into_iter().flatten() {
            let index = self
                .epochs
                .iter()
                .position(|epoch| epoch.identity == Some(identity))
                .or_else(|| {
                    self.epochs
                        .iter()
                        .position(|epoch| epoch.identity.is_none())
                })
                .or_else(|| self.epochs.iter().position(|epoch| !epoch.live));
            let Some(epoch) = index.and_then(|index| self.epochs.get_mut(index)) else {
                self.identity_unavailable();
                continue;
            };
            if epoch.identity != Some(identity) {
                if epoch.identity.is_some() {
                    increment(&mut self.omitted_epochs, &mut self.overflow);
                    for _ in epoch.rows.iter().flatten() {
                        increment(&mut self.omitted_owners, &mut self.overflow);
                    }
                }
                epoch.identity = Some(identity);
                epoch.first = now;
                epoch.samples = 0;
                epoch.rows.fill(None);
                epoch.rolling.clear();
                epoch.reliable.clear();
            }
            epoch.live = true;
            epoch.last = now;
            increment(&mut epoch.samples, &mut self.overflow);
        }
        true
    }
    fn row(&mut self, identity: Identity, owner: Owner, now: u64) -> Option<&mut Row> {
        let Some(epoch) = self
            .epochs
            .iter_mut()
            .find(|epoch| epoch.live && epoch.identity == Some(identity))
        else {
            increment(&mut self.identity_errors, &mut self.overflow);
            return None;
        };
        let Some(slot) = epoch.rows.get_mut(owner.index()) else {
            increment(&mut self.identity_errors, &mut self.overflow);
            return None;
        };
        if slot.as_ref().is_none_or(|row| row.owner != owner) {
            if slot.is_some() {
                increment(&mut self.omitted_owners, &mut self.overflow);
            }
            *slot = Some(Row::new(owner, now));
        }
        let row = slot.as_mut()?;
        row.observe(now);
        Some(row)
    }
    pub(crate) fn sample_engine(&mut self, identity: Identity, now: u64, engine: &engine::Engine) {
        use engine::{CodecBufferSnapshot as Codec, RecoveryBufferSnapshot as Recovery};
        if let Some(snapshot) = engine.rolling_wait_snapshot(engine::Tick(now)) {
            if let Some(epoch) = self
                .epochs
                .iter_mut()
                .find(|v| v.live && v.identity == Some(identity))
                && epoch.rolling.capacity() == 1
            {
                if let Some(slot) = epoch.rolling.first_mut() {
                    *slot = snapshot;
                } else {
                    epoch.rolling.push(snapshot);
                }
            } else {
                increment(&mut self.identity_errors, &mut self.overflow);
            }
        }
        if let Some(snapshot) = engine.reliable_output_wait(Duration::from_micros(now)) {
            self.sample_reliable_output(identity, snapshot);
        }
        let local = engine.configuration().descriptor().local(self.role);
        // Called only after the periodic/terminal sampling gate. Swift's exact
        // payload and equation sums scan bounded retained channel state.
        engine.visit_codec_buffers(|snapshot| {
            let (owner, buffers) = match snapshot {
                Codec::Endpoint(buffers) => (Owner::Endpoint, buffers),
                Codec::Connection {
                    owner,
                    incarnation,
                    buffers,
                } => (
                    Owner::Connection {
                        owner: owner.index(),
                        incarnation,
                    },
                    buffers,
                ),
                Codec::SwiftPacking {
                    bytes,
                    capacity_bytes,
                } => {
                    if let Some(row) = self.row(identity, Owner::SwiftPacking, now) {
                        row.codec = true;
                        row.gauge(0, Some(bytes), Some(capacity_bytes));
                    }
                    return;
                }
                Codec::SwiftChannel { channel, buffers } => {
                    let owner = Owner::SwiftChannel {
                        channel: channel.index(),
                        send: buffers.send.is_some(),
                        receive: buffers.receive.is_some(),
                    };
                    if let Some(row) = self.row(identity, owner, now) {
                        row.swift(buffers);
                    }
                    return;
                }
            };
            if let Some(row) = self.row(identity, owner, now) {
                row.codec(buffers);
            }
        });
        let send = Bounds::from_profile(local.send().profile());
        let receive = Bounds::from_profile(local.receive().profile());
        engine.visit_recovery_buffers(|snapshot| {
            let (owner, storage) = match snapshot {
                Recovery::Endpoint(storage) => (Owner::Endpoint, storage),
                Recovery::Connection {
                    owner,
                    incarnation,
                    storage,
                } => (
                    Owner::Connection {
                        owner: owner.index(),
                        incarnation,
                    },
                    storage,
                ),
            };
            if let Some(row) = self.row(identity, owner, now) {
                row.recovery(storage, send, receive);
            }
        });
        engine.visit_staged_admission(Duration::from_micros(now), |snapshot| {
            let (owner, snapshot) = match snapshot {
                engine::StagedAdmissionSnapshot::Endpoint(snapshot) => (Owner::Endpoint, snapshot),
                engine::StagedAdmissionSnapshot::Connection {
                    owner,
                    incarnation,
                    snapshot,
                } => (
                    Owner::Connection {
                        owner: owner.index(),
                        incarnation,
                    },
                    snapshot,
                ),
            };
            if let Some(row) = self.row(identity, owner, now) {
                row.staged_admission = Some(snapshot);
            }
        });
    }
    pub(crate) fn finish_staged_admission(&mut self, now: u64) {
        let at = Duration::from_micros(now);
        for epoch in &mut self.epochs {
            if !epoch.live {
                continue;
            }
            for row in epoch.rows.iter_mut().flatten() {
                let Some(snapshot) = row.staged_admission else {
                    continue;
                };
                if snapshot.terminal_at.is_some() {
                    continue;
                }
                if epoch.last == now && row.active && row.last == now && snapshot.observed_at == at
                {
                    // A fresh owner observation proves that this exact source is
                    // still retained at the caller's metric-stop boundary.
                    row.staged_admission = Some(snapshot.censor(at));
                } else {
                    increment(&mut self.staged_terminal_unavailable, &mut self.overflow);
                }
            }
        }
    }
    pub(crate) fn finish_rolling_waits(
        &mut self,
        now: u64,
        boundary: crate::buffer_metrics::SourceBoundary,
    ) {
        let boundary = match boundary {
            crate::buffer_metrics::SourceBoundary::DriverDrop => RollingTerminal::DriverDrop,
            _ => RollingTerminal::MetricStop,
        };
        for epoch in &mut self.epochs {
            if !epoch.live {
                continue;
            }
            if let Some(snapshot) = epoch.rolling.first_mut() {
                if snapshot.terminal.is_some() {
                    continue;
                }
                if epoch.last == now && snapshot.observed_at == engine::Tick(now) {
                    *snapshot = snapshot.censor(engine::Tick(now), boundary);
                } else {
                    increment(&mut self.staged_terminal_unavailable, &mut self.overflow);
                }
            }
        }
    }
    fn sample_reliable_output(&mut self, identity: Identity, snapshot: ReliableOutput) {
        if let Some(epoch) = self
            .epochs
            .iter_mut()
            .find(|v| v.live && v.identity == Some(identity))
            && epoch.reliable.capacity() == 1
            && snapshot.epoch == identity.epoch
        {
            if let Some(slot) = epoch.reliable.first_mut() {
                *slot = snapshot;
            } else {
                epoch.reliable.push(snapshot);
            }
        } else {
            increment(&mut self.identity_errors, &mut self.overflow);
        }
    }
    pub(crate) fn finish_reliable_output(&mut self, now: u64) {
        let at = Duration::from_micros(now);
        for epoch in &mut self.epochs {
            if !epoch.live {
                continue;
            }
            if let Some(snapshot) = epoch.reliable.first_mut() {
                if snapshot.terminal_at.is_some() {
                    continue;
                }
                if epoch.last == now && snapshot.observed_at == at {
                    *snapshot = snapshot.censor(at);
                } else {
                    increment(&mut self.staged_terminal_unavailable, &mut self.overflow);
                }
            }
        }
    }
    pub(crate) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        write!(
            out,
            "{{\"definition\":\"sampled occupancy, not blocked time; high water is observed samples only; endpoint pools are shared across channels; independent owners preserve incarnation; Swift shared packing overlaps per-channel packing and is not additive; Swift source positions include gaps; equation payload bytes exclude coefficient metadata; repairs_due is work debt without allocated payload; absent fields are unavailable; no owner durations are combined\",\"sample_interval_us\":{SAMPLE_INTERVAL_US},\"local_role\":\"{:?}\",\"coverage\":\"codec Aligned/Packed/Rolling/Research and per-connection owners; Reliable ARQ retention and Swift shared packing/per-channel source/retry/equation/stream snapshots; Swift feedback/history/control and all Swift dependency waits, restored-source handoff waits, builder packing hold, FEC missing-equation dependencies, other recovery internals, history use, per-channel non-Swift receiver gauges and waits outside explicitly emitted interval sections remain unavailable\",\"retired_epochs_omitted\":{},\"retired_owner_generations_omitted\":{},\"identity_errors\":{},\"clock_regressions\":{},\"unsupported_codec_samples\":{},\"staged_terminal_unavailable\":{},\"counter_overflow\":{},\"epochs\":[",
            self.role,
            self.omitted_epochs,
            self.omitted_owners,
            self.identity_errors,
            self.clock_regressions,
            self.unsupported_codec_samples,
            self.staged_terminal_unavailable,
            self.overflow
        )?;
        let mut comma = false;
        for epoch in &self.epochs {
            let Some(identity) = epoch.identity else {
                continue;
            };
            if comma {
                write!(out, ",")?;
            }
            comma = true;
            write!(
                out,
                "{{\"epoch\":{},\"configuration_digest_hex\":\"",
                identity.epoch
            )?;
            for byte in identity.configuration {
                write!(out, "{byte:02x}")?;
            }
            write!(
                out,
                "\",\"live_at_last_sample\":{},\"first_sample_us\":{},\"last_sample_us\":{},\"samples\":{},\"owner_capacity\":{},\"owners\":[",
                epoch.live,
                epoch.first,
                epoch.last,
                epoch.samples,
                epoch.rows.len()
            )?;
            let mut row_comma = false;
            for row in epoch.rows.iter().flatten() {
                if row_comma {
                    write!(out, ",")?;
                }
                row_comma = true;
                match row.owner {
                    Owner::Endpoint => write!(
                        out,
                        "{{\"scope\":\"endpoint-shared\",\"owner\":null,\"incarnation\":null"
                    )?,
                    Owner::SwiftPacking => write!(
                        out,
                        "{{\"scope\":\"swift-shared-packing\",\"owner\":null,\"incarnation\":null,\"channel\":null"
                    )?,
                    Owner::SwiftChannel {
                        channel,
                        send,
                        receive,
                    } => write!(
                        out,
                        "{{\"scope\":\"swift-channel\",\"owner\":null,\"incarnation\":null,\"channel\":{channel},\"send_present\":{send},\"receive_present\":{receive}"
                    )?,
                    Owner::Connection { owner, incarnation } => write!(
                        out,
                        "{{\"scope\":\"independent-connection\",\"owner\":{owner},\"incarnation\":{incarnation}"
                    )?,
                }
                write!(
                    out,
                    ",\"first_sample_us\":{},\"last_sample_us\":{},\"samples\":{},\"sampled_in_latest_provider_observation\":{},\"codec_observed\":{},\"recovery_observed\":{},\"invalid_occupancy\":{},\"counter_overflow\":{},\"gauges\":[",
                    row.first,
                    row.last,
                    row.samples,
                    row.active,
                    row.codec,
                    row.recovery,
                    row.invalid,
                    row.overflow
                )?;
                let mut gauge_comma = false;
                let names: &[&str] = match row.owner {
                    Owner::SwiftPacking => &SWIFT_PACKING_NAMES,
                    Owner::SwiftChannel { .. } => &SWIFT_NAMES,
                    Owner::Endpoint | Owner::Connection { .. } => &NAMES,
                };
                for (name, gauge) in names.iter().zip(row.gauges) {
                    if gauge.samples == 0 {
                        continue;
                    }
                    if gauge_comma {
                        write!(out, ",")?;
                    }
                    gauge_comma = true;
                    write!(
                        out,
                        "{{\"name\":\"{name}\",\"samples\":{},\"used\":",
                        gauge.samples
                    )?;
                    optional(out, gauge.used)?;
                    write!(out, ",\"capacity\":")?;
                    optional(out, gauge.capacity)?;
                    write!(out, ",\"high_water\":")?;
                    optional(out, gauge.high_water)?;
                    write!(out, "}}")?;
                }
                write!(out, "],\"staged_admission\":")?;
                match row.staged_admission {
                    Some(snapshot) => write_staged_wait(out, snapshot)?,
                    None => write!(out, "null")?,
                }
                write!(out, "}}")?;
            }
            write!(out, "],\"rolling_waits\":")?;
            match epoch.rolling.first() {
                Some(snapshot) => rolling_wait_metrics::write(out, snapshot)?,
                None => write!(out, "null")?,
            }
            write!(out, ",\"reliable_output\":")?;
            match epoch.reliable.first() {
                Some(snapshot) => reliable_output_metrics::write(out, snapshot)?,
                None => write!(out, "null")?,
            }
            write!(out, "}}")?;
        }
        write!(out, "]}}")
    }
}

fn duration(out: &mut impl Write, value: Option<Duration>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{}", value.as_micros()),
        None => write!(out, "null"),
    }
}
fn write_wait_totals(out: &mut impl Write, totals: WaitTotals) -> io::Result<()> {
    write!(
        out,
        "{{\"completed_episodes\":{},\"completed_us\":{},\"maximum_completed_us\":{},\"censored_episodes\":{},\"censored_us\":{},\"maximum_censored_us\":{}}}",
        totals.completed_episodes,
        totals.completed.as_micros(),
        totals.maximum_completed.as_micros(),
        totals.censored_episodes,
        totals.censored.as_micros(),
        totals.maximum_censored.as_micros()
    )
}
fn write_staged_wait(out: &mut impl Write, snapshot: StagedWait) -> io::Result<()> {
    write!(
        out,
        "{{\"definition\":\"actual eligible refusal through same-source recovery admission; includes scheduling delay; reasons can overlap; union is this owner only; retired samples stop at their observation; microseconds truncate sub-microsecond portions\",\"observed_at_us\":{},\"terminal_at_us\":",
        snapshot.observed_at.as_micros()
    )?;
    duration(out, snapshot.terminal_at)?;
    write!(out, ",\"terminal_stage\":")?;
    match snapshot.terminal {
        Some(l2tunnel_aligned::staged_wait::Terminal::OwnerFailure) => {
            write!(out, "\"owner_failure\"")?
        }
        Some(l2tunnel_aligned::staged_wait::Terminal::MetricStop) => {
            write!(out, "\"pre_settlement_metric_stop\"")?
        }
        None => write!(out, "null")?,
    }
    write!(
        out,
        ",\"clock_regression\":{},\"identity_mismatch\":{},\"counter_overflow\":{},\"union\":",
        snapshot.clock_regression, snapshot.identity_mismatch, snapshot.overflow
    )?;
    write_wait_totals(out, snapshot.union)?;
    write!(out, ",\"reasons\":[")?;
    for (index, name) in ["send_capacity", "sequence_window"].into_iter().enumerate() {
        if index != 0 {
            write!(out, ",")?;
        }
        write!(
            out,
            "{{\"reason\":\"{name}\",\"refused_attempts\":{},\"totals\":",
            snapshot.refusals[index]
        )?;
        write_wait_totals(out, snapshot.reasons[index])?;
        write!(out, "}}")?;
    }
    write!(out, "],\"open_us\":")?;
    duration(out, snapshot.open)?;
    write!(out, ",\"pending\":")?;
    match snapshot.pending {
        None => write!(out, "null")?,
        Some(pending) => {
            write!(
                out,
                "{{\"source\":{},\"bytes\":{},\"first_refusal_us\":{},\"last_refusal_us\":{},\"reason_first_refusal_us\":[",
                pending.source,
                pending.bytes,
                pending.since.as_micros(),
                pending.last_refusal.as_micros()
            )?;
            duration(out, pending.reasons_since[0])?;
            write!(out, ",")?;
            duration(out, pending.reasons_since[1])?;
            write!(out, "]}}")?;
        }
    }
    write!(out, ",\"last_resolved\":")?;
    match snapshot.last_resolved {
        None => write!(out, "null")?,
        Some(last) => write!(
            out,
            "{{\"source\":{},\"bytes\":{},\"first_refusal_us\":{},\"resolved_at_us\":{},\"censored\":{}}}",
            last.source,
            last.bytes,
            last.since.as_micros(),
            last.at.as_micros(),
            last.censored
        )?,
    }
    write!(out, "}}")
}

#[derive(Clone, Copy)]
struct Bounds {
    send_records: usize,
    send_bytes: usize,
    receive_records: usize,
    receive_bytes: usize,
    history: Option<usize>,
}
impl Bounds {
    fn from_profile(profile: DirectionProfile<'_>) -> Option<Self> {
        use l2tunnel_recovery::{ArqConfig, CompactArqConfig};
        let legacy = |value: ArqConfig| Self {
            send_records: value.send_records,
            send_bytes: value.send_bytes,
            receive_records: value.receive_records,
            receive_bytes: value.receive_bytes,
            history: None,
        };
        let compact = |value: CompactArqConfig| {
            let bounds = value.bounds();
            Self {
                send_records: bounds.send_records,
                send_bytes: bounds.send_bytes,
                receive_records: bounds.receive_records,
                receive_bytes: bounds.receive_bytes,
                history: Some(value.history_entries()),
            }
        };
        Some(match profile {
            DirectionProfile::Aligned(config) => legacy(config.recovery.arq),
            DirectionProfile::Packed(config) => legacy(config.base.recovery.arq),
            DirectionProfile::AlignedCompact(config) => compact(config.recovery.arq()),
            DirectionProfile::PackedCompact(config) => compact(config.base.recovery.arq()),
            DirectionProfile::PerConnectionCompact(config) => {
                compact(config.compact.recovery.arq())
            }
            DirectionProfile::Swift(_)
            | DirectionProfile::Rolling { .. }
            | DirectionProfile::Research { .. } => return None,
        })
    }
}

fn increment(value: &mut u64, overflow: &mut bool) {
    match value.checked_add(1) {
        Some(next) => *value = next,
        None => *overflow = true,
    }
}
fn optional(out: &mut impl Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result = std::result::Result<(), Box<dyn std::error::Error>>;
    fn identity(epoch: u64, byte: u8) -> Identity {
        Identity {
            epoch,
            configuration: [byte; 32],
        }
    }

    #[test]
    fn cadence_identity_reuse_and_high_water_remain_separate() -> Result {
        let mut value = ProtocolBuffers::new(2, Role::Client)?;
        let heap = value.heap_bytes();
        let a = identity(7, 1);
        let b = identity(9, 2);
        assert!(value.due(0, false));
        assert!(value.begin(0, [Some(a), Some(b)]));
        value
            .row(a, Owner::Endpoint, 0)
            .ok_or("a")?
            .gauge(0, Some(3), Some(8));
        value
            .row(b, Owner::Endpoint, 0)
            .ok_or("b")?
            .gauge(0, Some(7), Some(8));
        assert!(!value.due(99_999, false));
        assert!(value.due(100_000, false));
        assert!(value.begin(100_000, [Some(b), Some(a)]));
        value
            .row(a, Owner::Endpoint, 100_000)
            .ok_or("a")?
            .gauge(0, Some(1), Some(8));
        assert_eq!(
            value.row(a, Owner::Endpoint, 100_000).ok_or("a")?.gauges[0].high_water,
            Some(3)
        );
        assert_eq!(
            value.row(b, Owner::Endpoint, 100_000).ok_or("b")?.gauges[0].high_water,
            Some(7)
        );
        let c = identity(7, 3); // Same epoch number with another digest must not inherit samples.
        assert!(value.begin(100_001, [Some(b), Some(c)]));
        let row = value.row(c, Owner::Endpoint, 100_001).ok_or("c")?;
        assert_eq!(row.gauges[0].high_water, None);
        row.gauge(0, Some(2), Some(8));
        assert_eq!(value.omitted_epochs, 1);
        assert_eq!(value.omitted_owners, 1);
        assert_eq!(value.heap_bytes(), heap);
        assert!(value.due(100_002, true));
        assert!(!value.begin(99_999, [Some(b), Some(c)]));
        assert_eq!(value.clock_regressions, 1);
        Ok(())
    }

    #[test]
    fn independent_incarnation_and_unavailable_history_are_explicit() -> Result {
        let mut value = ProtocolBuffers::new(2, Role::Server)?;
        let epoch = identity(1, 4);
        assert!(value.begin(0, [Some(epoch), None]));
        let first = Owner::Connection {
            owner: 1,
            incarnation: 8,
        };
        let row = value.row(epoch, first, 0).ok_or("first")?;
        row.gauge(16, Some(4), Some(8));
        row.gauge(26, None, Some(131_072));
        assert_eq!(row.gauges[26].used, None);
        assert_eq!(row.gauges[26].high_water, None);
        assert!(value.begin(100_000, [Some(epoch), None]));
        let next = Owner::Connection {
            owner: 1,
            incarnation: 9,
        };
        let row = value.row(epoch, next, 100_000).ok_or("next")?;
        assert_eq!(row.gauges[16].high_water, None);
        row.gauge(16, Some(9), Some(8));
        assert!(row.invalid);
        assert_eq!(value.omitted_owners, 1);
        assert!(
            value
                .row(
                    epoch,
                    Owner::Connection {
                        owner: 2,
                        incarnation: 1
                    },
                    100_000
                )
                .is_none()
        );
        let mut output = Vec::new();
        value.write(&mut output)?;
        let json: serde_json::Value = serde_json::from_slice(&output)?;
        assert_eq!(
            json["epochs"][0]["owners"][0]["scope"],
            "independent-connection"
        );
        assert_eq!(json["epochs"][0]["owners"][0]["incarnation"], 9);
        assert_eq!(json["epochs"][0]["owners"][0]["invalid_occupancy"], true);
        assert!(ProtocolBuffers::new(0, Role::Client).is_err());
        assert!(ProtocolBuffers::new(MAX_OWNERS + 1, Role::Client).is_err());
        Ok(())
    }
    #[test]
    fn staged_wait_terminal_requires_fresh_identity_sample() -> Result {
        use l2tunnel_aligned::staged_wait::{Pending, Snapshot, Terminal};
        let epoch = identity(4, 8);
        let mut value = ProtocolBuffers::new(1, Role::Client)?;
        let make = |at| Snapshot {
            observed_at: Duration::from_micros(at),
            terminal_at: None,
            terminal: None,
            refusals: [2, 0],
            reasons: [WaitTotals::default(); 2],
            union: WaitTotals::default(),
            pending: Some(Pending {
                source: 12,
                bytes: 77,
                since: Duration::from_micros(10),
                last_refusal: Duration::from_micros(15),
                reasons_since: [Some(Duration::from_micros(10)), None],
            }),
            open: Some(Duration::from_micros(at - 10)),
            last_resolved: None,
            clock_regression: false,
            identity_mismatch: false,
            overflow: false,
        };
        assert!(value.begin(20, [Some(epoch), None]));
        value
            .row(epoch, Owner::Endpoint, 20)
            .ok_or("row")?
            .staged_admission = Some(make(20));
        value.finish_staged_admission(30);
        assert_eq!(value.staged_terminal_unavailable, 1);
        assert!(
            value
                .row(epoch, Owner::Endpoint, 20)
                .ok_or("row")?
                .staged_admission
                .ok_or("snapshot")?
                .terminal_at
                .is_none()
        );
        assert!(value.begin(30, [Some(epoch), None]));
        value
            .row(epoch, Owner::Endpoint, 30)
            .ok_or("row")?
            .staged_admission = Some(make(30));
        value.finish_staged_admission(30);
        value.finish_staged_admission(40);
        let snapshot = value
            .row(epoch, Owner::Endpoint, 30)
            .ok_or("row")?
            .staged_admission
            .ok_or("snapshot")?;
        assert_eq!(snapshot.terminal, Some(Terminal::MetricStop));
        assert_eq!(snapshot.union.censored, Duration::from_micros(20));
        assert_eq!(snapshot.union.censored_episodes, 1);
        assert_eq!(snapshot.union.completed_episodes, 0);
        assert_eq!(snapshot.last_resolved.map(|last| last.source), Some(12));
        let mut output = Vec::new();
        value.write(&mut output)?;
        let json: serde_json::Value = serde_json::from_slice(&output)?;
        let wait = &json["epochs"][0]["owners"][0]["staged_admission"];
        assert_eq!(wait["terminal_stage"], "pre_settlement_metric_stop");
        assert_eq!(wait["union"]["censored_us"], 20);
        assert!(wait["open_us"].is_null());
        Ok(())
    }
    #[test]
    fn swift_channel_identity_preserves_asymmetry_and_epoch_high_water() -> Result {
        use l2tunnel_swift::diagnostics::{ChannelBuffers, ReceiverBuffers};
        let mut value = ProtocolBuffers::new(3, Role::Client)?;
        let heap = value.heap_bytes();
        let a = identity(11, 7);
        let owner = Owner::SwiftChannel {
            channel: 1,
            send: false,
            receive: true,
        };
        let buffers = ChannelBuffers {
            send: None,
            receive: Some(ReceiverBuffers {
                source_positions: 3,
                source_capacity_positions: 8,
                known_sources: 2,
                source_bytes: 7,
                source_capacity_bytes: 128,
                rows: 1,
                row_capacity: 4,
                row_bytes: 9,
                row_capacity_bytes: 72,
                stream_bytes: 5,
                stream_capacity_bytes: 128,
            }),
        };
        assert!(value.begin(1, [Some(a), None]));
        value
            .row(a, Owner::SwiftPacking, 1)
            .ok_or("packing")?
            .gauge(0, Some(0), Some(16));
        value.row(a, owner, 1).ok_or("channel")?.swift(buffers);
        assert!(!value.due(100_000, false));
        assert!(value.begin(100_001, [Some(a), None]));
        let mut smaller = buffers;
        smaller.receive.as_mut().ok_or("receive")?.stream_bytes = 1;
        value
            .row(a, owner, 100_001)
            .ok_or("channel")?
            .swift(smaller);
        let row = value.row(a, owner, 100_001).ok_or("channel")?;
        assert_eq!(row.gauges[10].used, Some(1));
        assert_eq!(row.gauges[10].high_water, Some(5));
        assert_eq!(row.gauges[0].samples, 0, "absent sender is not zero usage");
        assert!(
            row.staged_admission.is_none(),
            "retention cannot create a wait"
        );
        let mut output = Vec::new();
        value.write(&mut output)?;
        let json: serde_json::Value = serde_json::from_slice(&output)?;
        let channel = &json["epochs"][0]["owners"][1];
        assert_eq!(channel["scope"], "swift-channel");
        assert_eq!(channel["channel"], 1);
        assert_eq!(channel["send_present"], false);
        assert_eq!(channel["receive_present"], true);
        assert!(channel["owner"].is_null() && channel["incarnation"].is_null());
        assert_eq!(channel["gauges"].as_array().ok_or("gauges")?.len(), 6);
        let b = identity(11, 8);
        assert!(value.begin(100_002, [Some(b), None]));
        let fresh = value.row(b, owner, 100_002).ok_or("new digest")?;
        assert_eq!(fresh.gauges[10].high_water, None);
        fresh.swift(smaller);
        assert_eq!(fresh.gauges[10].high_water, Some(1));
        assert_eq!(value.heap_bytes(), heap, "sampling must not grow storage");
        assert!(
            value.row(a, owner, 100_002).is_none(),
            "retired epoch cannot update"
        );
        Ok(())
    }

    #[test]
    fn reliable_provider_uses_actual_sealed_head_and_fresh_terminal_identity() -> Result {
        use l2tunnel_recovery::{ArqConfig, EndpointRole, RecoveryContext};
        use l2tunnel_reliable::{OutboundBudget, Reliable, ReliableConfig, storage};
        let ms = Duration::from_millis;
        let config = ReliableConfig {
            arq: ArqConfig {
                max_source_bytes: 64,
                send_bytes: 512,
                receive_bytes: 512,
                send_records: 8,
                receive_records: 8,
                initial_rto: ms(100),
                maximum_rto: ms(800),
                ack_delay: ms(1),
                max_retries: 8,
            },
            fec: l2tunnel_fec::DecoderConfig {
                block: l2tunnel_fec::BlockConfig {
                    max_sources: 3,
                    max_source_bytes: 108,
                    max_packet_bytes: 169,
                    max_work_per_symbol: 4096,
                },
                max_generations: 4,
                max_symbols_per_generation: 6,
                max_reserved_bytes: 50_000,
                max_lifetime_ticks: 50,
                generation_window: 32,
            },
            repair_symbols: 2,
            flush_after: ms(5),
            max_restored_packets: 16,
            max_restored_bytes: 4096,
            outer_overhead_bytes: 28,
        };
        let plan = storage::Plan::for_duplex(config, config)?.with_output_diagnostics()?;
        let mut endpoint = Reliable::new_reserved_with_plan(
            plan,
            RecoveryContext {
                session: 0x1234,
                epoch: 7,
                role: EndpointRole::Initiator,
            },
            storage::Limits {
                capacity_bytes: plan.capacity_bytes(),
            },
        )?;
        endpoint.enable_compact_wire_with_overheads(37, 49)?;
        endpoint.submit(b"actual retained FEC source", Duration::ZERO)?;
        let mut packet = vec![0; endpoint.max_packet_bytes()];
        endpoint.poll_data(
            Duration::ZERO,
            &mut packet,
            &mut OutboundBudget {
                packets: 8,
                wire_bytes: 4096,
            },
        )?;
        assert_eq!(
            endpoint.poll_data(ms(5), &mut packet, &mut OutboundBudget::default())?,
            None
        );
        let mut provider = ProtocolBuffers::new(1, Role::Client)?;
        let base_heap = provider.heap_bytes();
        provider.configure_reliable_output()?;
        let heap = provider.heap_bytes();
        assert_eq!(heap - base_heap, 2 * std::mem::size_of::<ReliableOutput>());
        let epoch = identity(7, 6);
        assert!(provider.begin(5_000, [Some(epoch), None]));
        provider.sample_reliable_output(
            epoch,
            endpoint.output_wait_snapshot(ms(5)).ok_or("actual wait")?,
        );
        provider
            .row(epoch, Owner::Endpoint, 5_000)
            .ok_or("row")?
            .recovery(endpoint.storage(), None, None);
        // A later cached terminal cannot invent another millisecond of waiting.
        provider.finish_reliable_output(6_000);
        assert_eq!(provider.staged_terminal_unavailable, 1);
        assert!(provider.begin(6_000, [Some(epoch), None]));
        provider.sample_reliable_output(
            epoch,
            endpoint.output_wait_snapshot(ms(6)).ok_or("fresh wait")?,
        );
        provider.finish_reliable_output(6_000);
        let mut output = Vec::new();
        provider.write(&mut output)?;
        let json: serde_json::Value = serde_json::from_slice(&output)?;
        let wait = &json["epochs"][0]["reliable_output"];
        assert_eq!(wait["epoch"], 7);
        assert_eq!(wait["union"]["censored_episodes"], 1);
        assert_eq!(wait["union"]["censored_us"], 1_000);
        assert_eq!(wait["last_resolved"]["operation"]["generation"], 0);
        assert!(wait["pending"].is_null());
        assert_eq!(provider.heap_bytes(), heap);
        assert!(
            endpoint
                .output_wait_snapshot(ms(6))
                .ok_or("live protocol owner")?
                .pending
                .is_some()
        );
        // Compact R0 has no Block policy; retain baseline used gauges and unknown FEC.
        let row = provider.row(epoch, Owner::Endpoint, 6_000).ok_or("row")?;
        let mut compact = Row::new(
            Owner::Connection {
                owner: 0,
                incarnation: 1,
            },
            6_000,
        );
        compact.recovery(
            l2tunnel_reliable::Storage {
                building_packets: 2,
                outbound_packets: 3,
                restored_packets: 4,
                ..l2tunnel_reliable::Storage::default()
            },
            None,
            None,
        );
        assert_eq!(compact.gauges[20].used, Some(2));
        assert_eq!(compact.gauges[22].used, Some(3));
        assert_eq!(compact.gauges[24].used, Some(4));
        assert_eq!(compact.gauges[20].capacity, None);
        assert_eq!(compact.gauges[27].samples, 0);
        assert_eq!(row.gauges[27].used, Some(0));
        assert_eq!(row.gauges[27].capacity, Some(50_000));
        assert_eq!(row.gauges[32].used, None);
        assert!(row.gauges[32].capacity.is_some());
        Ok(())
    }
}

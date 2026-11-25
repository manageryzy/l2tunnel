//! Read-only codec gauges and actual admission refusals; clocks stay with the caller.
use super::*;

/// Exact stage that refused a real original Pipeline head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionBlock {
    /// Authenticated native-delivery credit cannot admit this original packet.
    NativeDeliveryWindow,
    /// Swift's shared native packing budget refused before compression.
    SwiftPackingQueue,
    /// An earlier original still owns the selected codec's one native stage.
    CodecStage,
    /// The selected connection owner has stopped original admission for retirement.
    ConnectionRetirement,
    /// One source-free native ACK already owns this connection's output slot.
    ConnectionUnreliableSlot,
}

/// One actual refusal, not a prediction derived from a nonempty snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionRefusal {
    /// Nonreusable local Pipeline flow identity; scoped by the issuing Engine.
    pub flow: pipeline::FlowId,
    /// Original retained FIFO-head times, not a globally unique packet identity.
    pub timing: pipeline::PacketTiming,
    /// Actual Pipeline-selected channel or connection-owner index.
    pub channel: u16,
    /// Unchanged original packet length retained by Pipeline.
    pub bytes: usize,
    /// Stage that refused this attempt.
    pub reason: AdmissionBlock,
}

/// Actual nested codec snapshot, with per-connection identities preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecBufferSnapshot {
    /// The one shared Swift original-admission budget across all sending channels.
    SwiftPacking {
        /// Actual total packed bytes, not a sum of configured per-channel bounds.
        bytes: usize,
        /// The one actual shared byte bound.
        capacity_bytes: usize,
    },
    /// One Swift channel's actual send and receive buffers.
    SwiftChannel {
        /// Checked channel index, including asymmetric receive-only channels.
        channel: swift::records::ChannelId,
        /// Actual per-channel retention; absent directions remain None.
        buffers: swift::diagnostics::ChannelBuffers,
    },
    /// One shared Aligned/Packed/Rolling/Research endpoint.
    Endpoint(l2tunnel_codec::diagnostics::DuplexBuffers),
    /// One independently recovering connection owner.
    Connection {
        /// Checked route owner label; not authentication authority.
        owner: crate::connection_records::OwnerId,
        /// Current full incarnation, not a truncated route serial.
        incarnation: u64,
        /// Actual nested codec queues.
        buffers: l2tunnel_codec::diagnostics::DuplexBuffers,
    },
}

impl Engine {
    /// Visit actual selected codec buffers without allocation, polling or time changes.
    /// Receiver scans are bounded by configuration; callers choose sampling cadence.
    pub fn visit_codec_buffers(&self, mut visit: impl FnMut(CodecBufferSnapshot)) {
        match &self.owner {
            Owner::Aligned(owner) => {
                visit(CodecBufferSnapshot::Endpoint(owner.codec_buffer_snapshot()))
            }
            Owner::Packed(owner) => {
                visit(CodecBufferSnapshot::Endpoint(owner.codec_buffer_snapshot()))
            }
            Owner::Rolling(owner) => {
                visit(CodecBufferSnapshot::Endpoint(owner.codec_buffer_snapshot()))
            }
            Owner::Striped(_) => {}
            Owner::Research(owner) => {
                visit(CodecBufferSnapshot::Endpoint(owner.codec_buffer_snapshot()))
            }
            Owner::Connections(owner) => {
                owner
                    .collection
                    .visit_codec_buffers(|owner, incarnation, buffers| {
                        visit(CodecBufferSnapshot::Connection {
                            owner,
                            incarnation,
                            buffers,
                        });
                    })
            }
            Owner::Swift(owner) => {
                let engine = owner.engine();
                let (bytes, capacity_bytes) = engine.packing_buffer_snapshot();
                visit(CodecBufferSnapshot::SwiftPacking {
                    bytes,
                    capacity_bytes,
                });
                let channels = engine
                    .send_config()
                    .channels
                    .max(engine.receive_config().channels);
                for index in 0..channels {
                    // The actual Engine constructor checked every directional channel width.
                    if let Some(channel) = swift::records::ChannelId::new(index) {
                        visit(CodecBufferSnapshot::SwiftChannel {
                            channel,
                            buffers: engine.channel_buffer_snapshot(channel),
                        });
                    }
                }
            }
        }
    }
}

/// Actual shared or independent reliable recovery retention, without polling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryBufferSnapshot {
    /// One shared Aligned or Packed recovery owner.
    Endpoint(l2tunnel_reliable::Storage),
    /// One independently recovering connection and its full incarnation.
    Connection {
        /// Actual route owner, not a shared MUX channel.
        owner: crate::connection_records::OwnerId,
        /// Full current incarnation of this actual recovery owner.
        incarnation: u64,
        /// Actual retained recovery payloads and staging.
        storage: l2tunnel_reliable::Storage,
    },
}

impl Engine {
    /// Visit actual Reliable/ARQ retention without allocation, time or I/O.
    /// Other recovery families have distinct owners and are not represented here.
    pub fn visit_recovery_buffers(&self, mut visit: impl FnMut(RecoveryBufferSnapshot)) {
        match &self.owner {
            Owner::Aligned(owner) => {
                visit(RecoveryBufferSnapshot::Endpoint(owner.recovery_storage()))
            }
            Owner::Packed(owner) => {
                visit(RecoveryBufferSnapshot::Endpoint(owner.recovery_storage()))
            }
            Owner::Connections(owner) => {
                owner
                    .collection
                    .visit_recovery_buffers(|owner, incarnation, storage| {
                        visit(RecoveryBufferSnapshot::Connection {
                            owner,
                            incarnation,
                            storage,
                        })
                    })
            }
            Owner::Swift(_) | Owner::Striped(_) | Owner::Rolling(_) | Owner::Research(_) => {}
        }
    }
}

/// One actual staged-source wait owner; external epoch/config identity stays with Engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedAdmissionSnapshot {
    /// One shared Aligned or Packed staged source.
    Endpoint(l2tunnel_aligned::staged_wait::Snapshot),
    /// One independent connection recovery owner.
    Connection {
        /// Actual fixed-cohort owner label.
        owner: crate::connection_records::OwnerId,
        /// Full current incarnation.
        incarnation: u64,
        /// Exact source identity, reason counters and interval populations.
        snapshot: l2tunnel_aligned::staged_wait::Snapshot,
    },
}
impl Engine {
    /// Visit exact retained-source admission wait summaries using only injected time.
    /// Unsupported recovery families produce no fabricated zero-valued owner.
    pub fn visit_staged_admission(
        &self,
        observed: std::time::Duration,
        mut visit: impl FnMut(StagedAdmissionSnapshot),
    ) {
        match &self.owner {
            Owner::Aligned(owner) => visit(StagedAdmissionSnapshot::Endpoint(
                owner.staged_admission_snapshot(observed),
            )),
            Owner::Packed(owner) => visit(StagedAdmissionSnapshot::Endpoint(
                owner.staged_admission_snapshot(observed),
            )),
            Owner::Connections(owner) => {
                owner
                    .collection
                    .visit_staged_admission(observed, |owner, incarnation, snapshot| {
                        visit(StagedAdmissionSnapshot::Connection {
                            owner,
                            incarnation,
                            snapshot,
                        })
                    })
            }
            Owner::Swift(_) | Owner::Striped(_) | Owner::Rolling(_) | Owner::Research(_) => {}
        }
    }
}

impl Engine {
    /// Exact selected Rolling/Research wait state, absent when diagnostics are disabled.
    pub fn rolling_wait_snapshot(
        &self,
        observed: Tick,
    ) -> Option<crate::rolling_records::waits::Snapshot> {
        match &self.owner {
            Owner::Rolling(owner) => owner.wait_snapshot(observed),
            Owner::Research(owner) => owner.wait_snapshot(observed),
            _ => None,
        }
    }
}

impl Engine {
    /// Actual shared Block/Direct ARQ sidecar. Other profiles remain explicitly absent;
    /// per-connection Compact ARQ has no builder or sealed FEC output queue.
    pub fn reliable_output_wait(
        &self,
        now: std::time::Duration,
    ) -> Option<l2tunnel_reliable::diagnostics::Snapshot> {
        match &self.owner {
            Owner::Aligned(owner) => owner.recovery_output_wait(now),
            Owner::Packed(owner) => owner.recovery_output_wait(now),
            _ => None,
        }
    }
}

impl Engine {
    /// Actual shared ordered recovery-to-codec handoff timing, absent when not prepaid.
    /// Preview and independent connection owners are not covered by this single-slot observer.
    pub fn receiver_handoff_wait(
        &self,
        now: std::time::Duration,
    ) -> Option<l2tunnel_aligned::receiver_handoff::Snapshot> {
        match &self.owner {
            Owner::Aligned(owner) => owner.receiver_handoff_snapshot(now),
            Owner::Packed(owner) => owner.receiver_handoff_snapshot(now),
            _ => None,
        }
    }

    /// Payload bytes currently queued in Pipeline/MUX for one sending channel.
    pub fn channel_queued_bytes(&self, channel: u16) -> usize {
        self.pipeline.channel_queued_bytes(channel)
    }

    /// Look up the local Pipeline flow ID matching a native packet's canonical
    /// symmetric flow key, without mutating Pipeline state or idle timers.
    pub fn lookup_flow_id(&self, packet: &[u8]) -> Option<u64> {
        let classified = self.pipeline.classify(packet).ok()?;
        self.pipeline
            .flow(&classified.key)
            .map(|snap| snap.binding.id.0)
    }

    /// Snapshot protocol-specific recovery/coding counters without mutation or I/O.
    pub fn recovery_metrics(&self) -> RecoveryMetrics {
        match &self.owner {
            Owner::Swift(owned) => {
                let engine = owned.engine();
                let count = engine
                    .send_config()
                    .channels
                    .max(engine.receive_config().channels);
                let mut channels = Vec::with_capacity(count);
                for index in 0..count {
                    if let Some(stats) = engine.channel_stats(index) {
                        channels.push(SwiftChannelMetrics {
                            channel: index as u16,
                            send: stats.send,
                            receive: stats.receive,
                        });
                    }
                }
                RecoveryMetrics::Swift { channels }
            }
            Owner::Aligned(endpoint) => RecoveryMetrics::Reliable {
                arq: endpoint.arq_statistics(),
                reliable: endpoint.statistics(),
            },
            Owner::Packed(endpoint) => RecoveryMetrics::Reliable {
                arq: endpoint.arq_statistics(),
                reliable: endpoint.statistics(),
            },
            Owner::Rolling(endpoint) => {
                let st = endpoint.statistics();
                RecoveryMetrics::Rolling {
                    admitted: st.admitted,
                    handed: st.handed,
                    committed: st.committed,
                }
            }
            Owner::Research(_) | Owner::Striped(_) | Owner::Connections(_) => {
                RecoveryMetrics::Other
            }
        }
    }
}

/// Per-channel Swift sender and receiver statistics for CSR publication (`MCSR-05`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwiftChannelMetrics {
    /// Zero-based Swift channel index.
    pub channel: u16,
    /// Current send-direction observation, when this channel sends.
    pub send: Option<swift::records::SenderObservation>,
    /// Current receive-direction counters, when this channel receives.
    pub receive: Option<swift::ReceiverStats>,
}

/// Read-only protocol recovery/coding snapshot for CSR publication (`MCSR-05`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RecoveryMetrics {
    /// Swift per-channel ARQ + sliding-window FEC counters.
    Swift {
        /// Indexed active channels across send and receive widths.
        channels: Vec<SwiftChannelMetrics>,
    },
    /// Aligned or Packed Reliable (selective-repeat ARQ + Cauchy block FEC) counters.
    Reliable {
        /// Underlying ARQ statistics.
        arq: l2tunnel_recovery::Statistics,
        /// Reliable FEC/envelope statistics.
        reliable: l2tunnel_reliable::Statistics,
    },
    /// Rolling FEC endpoint statistics.
    Rolling {
        /// Native frames admitted.
        admitted: u64,
        /// Complete outputs handed to carrier.
        handed: u64,
        /// Whole native writes committed.
        committed: u64,
    },
    /// Other profile families (Research receiver is published via `research_receiver`).
    #[default]
    Other,
}

impl ProfileIdentity {
    /// Zero-based channel or owner index for per-channel RX metering (`MCSR-07`).
    pub fn channel_index(self) -> u16 {
        match self {
            Self::Swift(identity) => identity.channel.index() as u16,
            Self::Connection(identity) => identity.owner.index(),
            Self::UnreliableNative(identity) => identity.owner.index(),
            Self::Aligned(identity)
            | Self::Packed(identity)
            | Self::Rolling(identity)
            | Self::Striped(identity)
            | Self::Research(identity) => identity.channel.0 as u16,
        }
    }
}

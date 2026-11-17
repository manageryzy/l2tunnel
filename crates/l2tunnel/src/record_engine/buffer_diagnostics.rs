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

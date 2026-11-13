use super::runtime;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Explicit experimental carrier, independent of retained raw TCP/TLS.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// Original TLS-to-protected-packet runtime, explicitly selected at startup.
    RawPacketV1,
}
/// No UDP cover or automatic fallback is selected by this profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cover {
    /// No separately selected UDP cover.
    None,
}
/// Native common MUX with existing TAP/system or transparent-TUN DRR policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Traffic {
    /// Existing native common-MUX TAP/system or transparent-TUN policy.
    System,
}
/// Requested or actually authenticated selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    /// Exact startup-only carrier.
    pub carrier: Carrier,
    /// No independently selected UDP framing profile.
    pub udp_cover: Cover,
    /// Native system traffic policy, never TCP window ownership.
    pub traffic: Traffic,
}
impl Default for Selection {
    fn default() -> Self {
        Self {
            carrier: Carrier::RawPacketV1,
            udp_cover: Cover::None,
            traffic: Traffic::System,
        }
    }
}
/// Implementation and qualification are separate from actual session selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// The real runtime is wired through original-owner factories.
    pub runtime_implemented: bool,
    /// Only separately recorded native labs can qualify a native path.
    pub native_qualified: bool,
    /// This experimental pacing allowance is not real congestion control.
    pub congestion_control: bool,
    /// Protected coordinated clean drain is not provided by this runtime.
    pub clean_drain: bool,
    /// Startup policy is immutable; no runtime policy reload exists.
    pub hot_reload: bool,
}
/// Actual native reservation/flush/device accounting, never a TCP advertised window.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeFlight {
    /// Actual original-native accounting in the named domain.
    pub admitted_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub admitted_records: u64,
    /// Actual original-native accounting in the named domain.
    pub delivered_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub delivered_records: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_records: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_total_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub flushed_total_records: u64,
    /// Actual original-native accounting in the named domain.
    pub outstanding_bytes: u64,
    /// Actual original-native accounting in the named domain.
    pub outstanding_records: u64,
    /// Actual original-native accounting in the named domain.
    pub target_bytes: u64,
    /// Latest genuine flush-to-feedback duration, absent before first observation.
    pub raw_rtt_micros: Option<u64>,
    /// EWMA from that same sample; may be retained after its TTL expires.
    pub smoothed_rtt_micros: Option<u64>,
    /// Original authenticated feedback timestamp relative to runtime startup.
    pub sample_at_micros: Option<u64>,
    /// Whether the retained sample is currently within policy TTL.
    pub sample_fresh: bool,
    /// Metadata still waiting for remote delivery or observed original send.
    pub retained_records: usize,
}
impl From<l2tunnel_flow_control::delivery_window::Status> for NativeFlight {
    fn from(s: l2tunnel_flow_control::delivery_window::Status) -> Self {
        Self {
            admitted_bytes: s.admitted.bytes,
            admitted_records: s.admitted.records,
            delivered_bytes: s.delivered.bytes,
            delivered_records: s.delivered.records,
            flushed_bytes: s.flushed.bytes,
            flushed_records: s.flushed.records,
            flushed_total_bytes: s.flushed_total.bytes,
            flushed_total_records: s.flushed_total.records,
            outstanding_bytes: s.outstanding.bytes,
            outstanding_records: s.outstanding.records,
            target_bytes: s.target_bytes,
            raw_rtt_micros: s.sample.map(|v| v.raw_micros),
            smoothed_rtt_micros: s.sample.map(|v| v.smoothed_micros),
            sample_at_micros: s.sample.map(|v| v.feedback_at.0),
            sample_fresh: s.sample_fresh,
            retained_records: s.retained_records,
        }
    }
}
/// Configured source-recovery geometry plus current retained occupancy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryWindow {
    /// Independent recovery-source capacity or retained occupancy.
    pub send_records_limit: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub receive_records_limit: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub send_bytes_limit: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub receive_bytes_limit: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub send_records: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub receive_records: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub send_bytes: usize,
    /// Independent recovery-source capacity or retained occupancy.
    pub receive_bytes: usize,
}
impl From<runtime::RecoveryWindow> for RecoveryWindow {
    fn from(s: runtime::RecoveryWindow) -> Self {
        Self {
            send_records_limit: s.send_records_limit,
            receive_records_limit: s.receive_records_limit,
            send_bytes_limit: s.send_bytes_limit,
            receive_bytes_limit: s.receive_bytes_limit,
            send_records: s.send_records,
            receive_records: s.receive_records,
            send_bytes: s.send_bytes,
            receive_bytes: s.receive_bytes,
        }
    }
}
/// Bounded aggregate observation; no per-packet, payload or secret fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Exact explicit startup request.
    pub requested: Selection,
    /// Present only on an Observer obtained from a real authenticated Session.
    pub effective: Option<Selection>,
    /// Separately scoped capability status.
    pub capabilities: Capabilities,
    /// Actual common authenticated profile; absent before setup succeeds.
    pub digest: Option<String>,
    /// Actual local lifecycle; stopped alone never implies clean close.
    pub phase: String,
    /// Native frames committed through common admission, per physical lane.
    pub admitted: [u64; 2],
    /// Recovery sources emitted, excluding retries.
    pub sources: [u64; 2],
    /// Fully reconstructed peer native frames.
    pub received: [u64; 2],
    /// Frames actually written to the native device.
    pub delivered: [u64; 2],
    /// Actual authenticated peer native confirmations.
    pub peer_delivered: [u64; 2],
    /// Carrier staging counts; these are not physical sends.
    pub staged: [u64; 2],
    /// Actual runtime I/O category when available; no successful terminal claim.
    pub fault: Option<String>,
    /// Explicit selected runtime profile, distinct from unchanged lower wire carrier.
    pub runtime_profile: String,
    /// Per-lane native byte windows, absent on receive-only lanes/setup.
    pub delivery: [Option<NativeFlight>; 2],
    /// Independent configured recovery caps and actual retained source banks.
    pub recovery: [Option<RecoveryWindow>; 2],
    /// Native bytes retained in each incoming hard bank.
    pub native_pending_bytes: [u64; 2],
    /// Native records retained in each incoming hard bank.
    pub native_pending_records: [usize; 2],
    /// Local common-MUX queue packet ceiling.
    pub local_queue_packets_limit: usize,
    /// Local common-MUX queue byte ceiling.
    pub local_queue_bytes_limit: usize,
    /// Actual local common-MUX queue packets.
    pub local_queue_packets: usize,
    /// Actual local common-MUX queue bytes.
    pub local_queue_bytes: usize,
    /// Configured shared raw IP-byte pacing cap, not observed throughput.
    pub wire_bytes_per_second: u64,
    /// Configured shared raw packet pacing cap.
    pub wire_packets_per_second: u32,
}
/// Cloneable observer for one coalesced actual status slot; it owns no data pump.
#[derive(Clone)]
pub struct Observer {
    receiver: watch::Receiver<runtime::Status>,
    digest: Option<[u8; 32]>,
}
impl Observer {
    pub(super) fn new(
        receiver: watch::Receiver<runtime::Status>,
        digest: Option<[u8; 32]>,
    ) -> Self {
        Self { receiver, digest }
    }
    /// Copy a bounded requested/effective runtime observation for UI or local API.
    pub fn snapshot(&self) -> Snapshot {
        let s = self.receiver.borrow();
        Snapshot {
            requested: Selection::default(),
            effective: self.digest.map(|_| Selection::default()),
            capabilities: Capabilities {
                runtime_implemented: true,
                native_qualified: false,
                congestion_control: false,
                clean_drain: false,
                hot_reload: false,
            },
            digest: self
                .digest
                .map(|d| d.iter().map(|b| format!("{b:02x}")).collect()),
            phase: format!("{:?}", s.phase),
            admitted: s.admitted,
            sources: s.sources,
            received: s.received,
            delivered: s.delivered,
            peer_delivered: s.peer_delivered,
            staged: s.staged,
            fault: s.fault.map(|k| format!("{k:?}")),
            runtime_profile: super::PROFILE.into(),
            delivery: s.delivery.map(|v| v.map(Into::into)),
            recovery: s.recovery.map(|v| v.map(Into::into)),
            native_pending_bytes: s.native_pending_bytes,
            native_pending_records: s.native_pending_records,
            local_queue_packets_limit: s.local_queue_packets_limit,
            local_queue_bytes_limit: s.local_queue_bytes_limit,
            local_queue_packets: s.local_queue_packets,
            local_queue_bytes: s.local_queue_bytes,
            wire_bytes_per_second: s.wire_bytes_per_second,
            wire_packets_per_second: s.wire_packets_per_second,
        }
    }
}

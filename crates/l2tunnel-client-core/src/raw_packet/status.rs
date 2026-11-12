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
    /// No independently selected UDP resemblance profile.
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
        }
    }
}

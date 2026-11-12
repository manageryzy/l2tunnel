use super::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
/// Requested and actually authenticated carrier, without automatic fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// Protected custom UDP with retained TLS bootstrap.
    Udp,
    /// Genuine maintained QUIC with datagrams.
    Quic,
}
/// Custom UDP resemblance profile, never interoperability evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cover {
    /// Genuine QUIC has no custom UDP cover.
    NotApplicable,
    /// Custom OpenVPN resemblance only.
    OpenVpnLike,
    /// Custom QUIC resemblance only.
    QuicLike,
}
impl From<udp::CoverProfile> for Cover {
    fn from(c: udp::CoverProfile) -> Self {
        match c {
            udp::CoverProfile::OpenVpnLike => Self::OpenVpnLike,
            udp::CoverProfile::QuicLike => Self::QuicLike,
        }
    }
}
/// Authenticated native packet layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// Native Ethernet frames.
    Tap,
    /// Transparent IP packets.
    Tun,
}
/// Actual one-lane or paired two-lane selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneMode {
    /// One bidirectional carrier.
    Full,
    /// Two paired directional carriers.
    Half,
}
/// Common MUX policy; neither variant owns endpoint TCP windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineProfile {
    /// TAP retains endpoint/system TCP and common FIFO/MUX admission.
    TapSystem,
    /// Transparent TUN uses bounded per-flow DRR admission.
    TunDrr,
}
/// Actual local lifecycle, independent of delivery or clean closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Complete original full/pair authentication succeeded.
    Authenticated,
    /// The sole runtime owner has started.
    Forwarding,
    /// The actual owner returned an error.
    Failed,
    /// The owner or its run future was dropped.
    Cancelled,
}
/// Bounded non-secret actual session selection and lifecycle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Explicit immutable record/recovery profile.
    pub profile: String,
    /// Original carrier request.
    pub requested_carrier: Carrier,
    /// Carrier authenticated by the original owner.
    pub effective_carrier: Carrier,
    /// Original cover request; not applicable to genuine QUIC.
    pub requested_cover: Cover,
    /// Actual authenticated cover.
    pub effective_cover: Cover,
    /// Actual native packet layer.
    pub layer: Layer,
    /// Actual carrier count/direction mode.
    pub duplex: LaneMode,
    /// Actual derived common admission policy.
    pub pipeline: PipelineProfile,
    /// Common channel budget.
    pub channels: u16,
    /// Selected coding support bound; no large-window qualification.
    pub window: usize,
    /// Exact source payload bound.
    pub max_payload: usize,
    /// Startup-bound epoch.
    pub epoch: u64,
    /// Complete immutable profile digest, lowercase hexadecimal.
    pub digest: String,
    /// Actual local lifecycle.
    pub phase: Phase,
    /// No runtime configuration switch is implemented.
    pub hot_reload: bool,
    /// No coordinated clean-close protocol is implemented.
    pub clean_drain: bool,
    /// This client does not own endpoint TCP windows.
    pub tcp_window_ownership: bool,
    /// Separate privileged evidence is still required.
    pub native_qualified: bool,
    /// W8192 service has not been qualified by this slice.
    pub large_window_qualified: bool,
    /// Only a bounded non-secret I/O error category is retained.
    pub failure: Option<String>,
}
/// Cloneable single-slot observation; never another carrier or drain owner.
#[derive(Clone)]
pub struct Observer(Arc<Mutex<Snapshot>>);
impl Observer {
    pub(crate) fn new(
        c: ConnectionConfig,
        r: runtime::Config,
        carrier: Carrier,
        cover: Cover,
        digest: l2tunnel_core::ConfigDigest,
    ) -> Self {
        let tap = c.layer == l2tunnel_device::PacketLayer::Ethernet;
        Self(Arc::new(Mutex::new(Snapshot {
            profile: PROFILE.into(),
            requested_carrier: carrier,
            effective_carrier: carrier,
            requested_cover: cover,
            effective_cover: cover,
            layer: if tap { Layer::Tap } else { Layer::Tun },
            duplex: if c.duplex == l2tunnel_core::Duplex::Full {
                LaneMode::Full
            } else {
                LaneMode::Half
            },
            pipeline: if tap {
                PipelineProfile::TapSystem
            } else {
                PipelineProfile::TunDrr
            },
            channels: r.pipeline.flows.channels,
            window: r.scheduler.recovery.window,
            max_payload: r.scheduler.recovery.max_payload,
            epoch: r.epoch,
            digest: digest.0.iter().map(|b| format!("{b:02x}")).collect(),
            phase: Phase::Authenticated,
            hot_reload: false,
            clean_drain: false,
            tcp_window_ownership: false,
            native_qualified: false,
            large_window_qualified: false,
            failure: None,
        })))
    }
    /// Read the most recent actual bounded state without acquiring runtime authority.
    pub fn snapshot(&self) -> Snapshot {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub(super) fn phase(&self, phase: Phase) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .phase = phase;
    }
    pub(super) fn failed(&self, error: &io::Error) {
        let mut s = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.phase = Phase::Failed;
        s.failure = Some(format!("{:?}", error.kind()));
    }
}

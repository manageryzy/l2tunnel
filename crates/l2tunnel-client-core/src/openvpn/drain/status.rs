use super::{carrier, runtime};
use serde::{Deserialize, Deserializer, Serialize};
use std::io;
/// Actual authenticated physical identity; never a caller-asserted capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Binding {
    /// One verified full-duplex lane.
    Full {
        /// Fresh authenticated session ID.
        session: [u8; 16],
        /// Accepted native-profile digest.
        config: [u8; 32],
    },
    /// Two genuinely joined complementary lanes.
    Paired {
        /// Join identity bound to both real sessions and identities.
        pair: [u8; 32],
        /// Accepted client-to-server then server-to-client digests.
        configs: [[u8; 32]; 2],
    },
}
impl Binding {
    pub(super) fn full(info: l2tunnel_auth::SessionInfo) -> Self {
        Self::Full {
            session: info.session_id,
            config: info.config.digest.0,
        }
    }
    pub(super) fn paired(info: carrier::PairInfo) -> Self {
        Self::Paired {
            pair: info.digest,
            configs: info.lanes.map(|v| v.config.digest.0),
        }
    }
}
/// Bounded acceptance and immutable terminal state, without live queue claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Actual authenticated identity.
    pub binding: Binding,
    /// A local one-shot stop request was successfully submitted.
    pub drain_accepted: bool,
    /// Actual runtime outcome, or absent while the retained runner is active.
    pub terminal: Option<Terminal>,
}
/// Actual outcome; successful submission is represented separately.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Terminal {
    /// Both native prefixes and original carrier owners completed in time.
    Closed {
        /// Counters copied from the actual successful receipt.
        report: CloseReport,
    },
    /// Actual runtime failure with bounded retained ownership evidence.
    Failed {
        /// OS error preserved independently of bounded diagnostics.
        error: Failure,
        /// Exact adapter inventory supplied by the failing runtime.
        progress: PartialProgress,
    },
    /// The original runner was dropped; no final inventory is invented.
    Cancelled,
}
// Serde's internally tagged unit variant accepts extra fields even with
// deny_unknown_fields. Decode through a strict empty struct variant instead.
impl<'de> Deserialize<'de> for Terminal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Strict {
            Closed {
                report: CloseReport,
            },
            Failed {
                error: Failure,
                progress: PartialProgress,
            },
            Cancelled {},
        }
        Ok(match Strict::deserialize(d)? {
            Strict::Closed { report } => Self::Closed { report },
            Strict::Failed { error, progress } => Self::Failed { error, progress },
            Strict::Cancelled {} => Self::Cancelled,
        })
    }
}
/// Exact confirmed native/source prefix.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceCounters {
    /// Whole native packets.
    pub packets: u64,
    /// Original native bytes.
    pub native_bytes: u64,
    /// Admitted carrier source count.
    pub sources: u64,
    /// Admitted carrier source bytes.
    pub source_bytes: u64,
}
impl From<carrier::NativeFence> for FenceCounters {
    fn from(v: carrier::NativeFence) -> Self {
        Self {
            packets: v.packets,
            native_bytes: v.native_bytes,
            sources: v.sources,
            source_bytes: v.source_bytes,
        }
    }
}
/// Final counters from an actually completed physical carrier owner.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarrierStats {
    /// Sources admitted to recovery.
    pub admitted_sources: u64,
    /// Sources consumed by the adapter, not independently native delivery.
    pub consumed_sources: u64,
    /// All charged datagrams, including control and retries.
    pub admitted_datagrams: u64,
    /// Complete IP bytes charged at admission.
    pub admitted_ip_bytes: u64,
    /// Writes actually accepted by the UDP socket.
    pub transmitted_datagrams: u64,
    /// Valid decrypted internal TLS messages.
    pub tls_messages: u64,
}
impl From<carrier::CloseReceipt> for CarrierStats {
    fn from(v: carrier::CloseReceipt) -> Self {
        let s = v.status;
        Self {
            admitted_sources: s.admitted_packets,
            consumed_sources: s.delivered_packets,
            admitted_datagrams: s.admitted_datagrams,
            admitted_ip_bytes: s.admitted_ip_bytes,
            transmitted_datagrams: s.transmitted_datagrams,
            tls_messages: s.tls_messages,
        }
    }
}
/// Fixed physical-lane cardinality, in canonical bulk-direction order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "lanes",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CarrierReport {
    /// One full-duplex owner.
    Full(CarrierStats),
    /// Client-to-server and server-to-client owners.
    Paired([CarrierStats; 2]),
}
/// Successful native confirmation and original carrier shutdown counters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseReport {
    /// Local accepted prefix delivered to the peer's native device.
    pub local: FenceCounters,
    /// Peer prefix delivered to this native device.
    pub peer: FenceCounters,
    /// Actual original carrier close receipts.
    pub carrier: CarrierReport,
}
impl From<runtime::NativeDrainReceipt> for CloseReport {
    fn from(v: runtime::NativeDrainReceipt) -> Self {
        Self {
            local: v.local.into(),
            peer: v.peer.into(),
            carrier: match v.carrier {
                runtime::CarrierClose::Full(v) => CarrierReport::Full(v.into()),
                runtime::CarrierClose::Paired(v) => CarrierReport::Paired(v.map(Into::into)),
            },
        }
    }
}
/// Stable, bounded classification; raw OS numbers and diagnostics stay separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Runtime-reported timeout; its precise cause is not inferred from the kind.
    TimedOut,
    /// A native or carrier owner closed unexpectedly.
    BrokenPipe,
    /// Unexpected stream end.
    UnexpectedEof,
    /// Invalid peer/frame data.
    InvalidData,
    /// Invalid local configuration or packet device contract.
    InvalidInput,
    /// Native permissions.
    PermissionDenied,
    /// Peer reset.
    ConnectionReset,
    /// Other runtime error; exact OS code is retained where available.
    Other,
}
/// Bounded non-secret error projection; diagnostics are at most 512 UTF-8 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    /// Stable classification.
    pub kind: FailureKind,
    /// Original errno, if supplied by the runtime.
    pub raw_os_error: Option<i32>,
    /// Bounded diagnostic; credential bytes are never included by these owners.
    #[serde(deserialize_with = "diagnostic")]
    pub diagnostic: String,
}
fn diagnostic<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if value.len() > 512 {
        return Err(serde::de::Error::custom(
            "native diagnostic exceeds 512 bytes",
        ));
    }
    Ok(value)
}
impl Failure {
    pub(super) fn from_error(error: &io::Error) -> Self {
        let mut diagnostic = error.to_string();
        let mut end = diagnostic.len().min(512);
        while !diagnostic.is_char_boundary(end) {
            end -= 1;
        }
        diagnostic.truncate(end);
        let kind = match error.kind() {
            io::ErrorKind::TimedOut => FailureKind::TimedOut,
            io::ErrorKind::BrokenPipe => FailureKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof => FailureKind::UnexpectedEof,
            io::ErrorKind::InvalidData => FailureKind::InvalidData,
            io::ErrorKind::InvalidInput => FailureKind::InvalidInput,
            io::ErrorKind::PermissionDenied => FailureKind::PermissionDenied,
            io::ErrorKind::ConnectionReset => FailureKind::ConnectionReset,
            _ => FailureKind::Other,
        };
        Self {
            kind,
            raw_os_error: error.raw_os_error(),
            diagnostic,
        }
    }
}
/// Actual adapter error inventory; pending admission remains explicitly uncertain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialProgress {
    /// Observed accepted native and admitted source prefix.
    pub accepted: FenceCounters,
    /// Whole sources consumed by the adapter.
    pub sources_received: u64,
    /// Source bytes consumed by the adapter.
    pub source_bytes_received: u64,
    /// Whole decoded native packets.
    pub native_completed: u64,
    /// Decoded native bytes.
    pub native_bytes_completed: u64,
    /// Successful native writes.
    pub native_confirmed: u64,
    /// Bytes successfully written to the device.
    pub native_bytes_confirmed: u64,
    /// Retained outgoing fragments, including a possible pending admission.
    pub outbound_fragments: usize,
    /// Retained outgoing fragment bytes.
    pub outbound_bytes: usize,
    /// Pending send may already be admitted; its result has not been observed.
    pub admission_in_flight: bool,
    /// Incomplete native records.
    pub reassembly_messages: usize,
    /// Bytes reserved for incomplete native records.
    pub reassembly_bytes: usize,
    /// Complete native packets waiting for successful device writes.
    pub pending_native_packets: usize,
    /// Complete native bytes waiting for successful device writes.
    pub pending_native_bytes: usize,
}
impl From<runtime::DrainProgress> for PartialProgress {
    fn from(v: runtime::DrainProgress) -> Self {
        Self {
            accepted: v.accepted.into(),
            sources_received: v.sources_received,
            source_bytes_received: v.source_bytes_received,
            native_completed: v.native_completed,
            native_bytes_completed: v.native_bytes_completed,
            native_confirmed: v.native_confirmed,
            native_bytes_confirmed: v.native_bytes_confirmed,
            outbound_fragments: v.outbound_fragments,
            outbound_bytes: v.outbound_bytes,
            admission_in_flight: v.admission_in_flight,
            reassembly_messages: v.reassembly_messages,
            reassembly_bytes: v.reassembly_bytes,
            pending_native_packets: v.pending_native_packets,
            pending_native_bytes: v.pending_native_bytes,
        }
    }
}

//! Experimental original-owner packet transition. Native integration is separate.
use super::phase_wire as wire;
use super::*;
pub use l2tunnel_datagram::Protection;
use l2tunnel_datagram::{
    CoverProfile, DatagramConfig, Direction, KeyContext, KeyGeneration, LaneId, PacketOpener,
    PacketSealer, SessionId,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Explicit final Records framing over the same original raw owners.
pub mod compact;
mod gate;
mod transaction;
use gate::{GateIo, GateState, SharedBudget};
pub use transaction::{PacketCarrier, PacketSetup, begin_packet_client, begin_packet_server};

/// Immutable lane limits copied from the genuine original-owner handoff.
/// These are byte capacities, not current occupancy or transfer authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaneLimits {
    /// Actual local receive/reorder horizon after the advertised-window cap.
    pub local_horizon_bytes: u64,
    /// Actual peer receive/reorder horizon after the advertised-window cap.
    pub peer_horizon_bytes: u64,
    /// Fixed bytes reserved beyond Data admission for feedback and controls.
    pub data_reserve_bytes: u64,
    /// Maximum local Data byte debt after the fixed peer-window reserve.
    pub send_data_capacity_bytes: u64,
    /// Maximum peer Data byte debt after the fixed local-window reserve.
    pub receive_data_capacity_bytes: u64,
}

/// Immutable experimental packet policy; all limits are authenticated before use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketPolicy {
    /// Complete IPv4 packet bound, 576..=1500, equal to the raw pair MTU.
    pub mtu: u16,
    /// Integrity is always required; this chooses AEAD or authenticated cleartext.
    pub protection: Protection,
    /// Per-lane incoming/outgoing data-record slots, 1..=64.
    pub queue_packets: u16,
    /// Finite byte reorder/window horizon, at most one MiB.
    pub horizon_bytes: u32,
    /// Minimum remaining post-transition useful wire-byte budget.
    pub minimum_transfer_bytes: u32,
    /// Shared lab IP-byte pacing rate for both lanes and every record kind.
    pub bytes_per_second: u64,
    /// Shared lab packet pacing rate.
    pub packets_per_second: u32,
    /// Shared finite byte burst.
    pub burst_bytes: u32,
    /// Shared finite packet burst.
    pub burst_packets: u16,
    /// Lifetime packet ceiling under each existing directional key.
    pub max_key_packets: u64,
    /// Lifetime authenticated plaintext-byte ceiling under each directional key.
    pub max_key_bytes: u64,
}
impl PacketPolicy {
    /// Conservative finite lab policy; this is not a congestion controller.
    pub fn new(mtu: u16) -> Self {
        Self {
            mtu,
            protection: Protection::ChaCha20Poly1305,
            queue_packets: 8,
            horizon_bytes: 32_768,
            minimum_transfer_bytes: 65_536,
            bytes_per_second: 1_048_576,
            packets_per_second: 2048,
            burst_bytes: 16_384,
            burst_packets: 32,
            max_key_packets: 1 << 20,
            max_key_bytes: 1 << 30,
        }
    }
    fn validate(self) -> Result<(), Error> {
        let m = u32::from(self.mtu);
        if !(576..=1500).contains(&self.mtu)
            || !(1..=64).contains(&self.queue_packets)
            || self.horizon_bytes < 9 * (m - 40)
            || self.horizon_bytes > 1_048_576
            || self.minimum_transfer_bytes == 0
            || self.bytes_per_second == 0
            || self.bytes_per_second > 1 << 40
            || self.packets_per_second == 0
            || self.packets_per_second > 1_000_000
            || self.burst_bytes < m
            || self.burst_bytes > 1_048_576
            || self.burst_packets == 0
            || self.burst_packets > 1024
            || !(1..=1 << 32).contains(&self.max_key_packets)
            || !(1..=1 << 40).contains(&self.max_key_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Exact original authenticated packet policy commitment for a requested base.
    /// Computing it grants no TLS, raw owner or transition authority.
    pub fn configuration_digest(self, base: ConfigDigest) -> Result<[u8; 32], Error> {
        self.digest(base)
    }
    fn digest(self, base: ConfigDigest) -> Result<[u8; 32], Error> {
        self.validate()?;
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(b"l2tunnel/raw-packet-policy/v1\0");
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&base.0);
        b.extend_from_slice(&[
            4,
            1,
            match self.protection {
                Protection::ChaCha20Poly1305 => 1,
                Protection::HmacSha256 => 2,
            },
            0,
        ]);
        b.extend_from_slice(&self.mtu.to_be_bytes());
        b.extend_from_slice(&self.queue_packets.to_be_bytes());
        b.extend_from_slice(&[4, 1, 1, 1]);
        b.extend_from_slice(&32u16.to_be_bytes());
        for n in [
            self.horizon_bytes,
            8 * (u32::from(self.mtu) - 40),
            self.minimum_transfer_bytes,
        ] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        b.extend_from_slice(&self.bytes_per_second.to_be_bytes());
        b.extend_from_slice(&self.packets_per_second.to_be_bytes());
        b.extend_from_slice(&self.burst_bytes.to_be_bytes());
        b.extend_from_slice(&self.burst_packets.to_be_bytes());
        b.extend_from_slice(&250_000u64.to_be_bytes());
        b.extend_from_slice(&32u16.to_be_bytes());
        b.extend_from_slice(&250_000u64.to_be_bytes());
        b.push(1);
        for n in [
            5_000_000u64,
            15_000_000,
            self.max_key_packets,
            self.max_key_bytes,
        ] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        for version in [1u16, 1, 2, 1, 1] {
            b.extend_from_slice(&version.to_be_bytes());
        }
        for n in [48u16, 128, 104, 280, 104, 8] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        b.extend_from_slice(&1u16.to_be_bytes());
        for n in [1_048_576u64, 2_097_152, 1_048_576] {
            b.extend_from_slice(&n.to_be_bytes());
        }
        b.extend_from_slice(&[1, 1, 1, 0]);
        Ok(profile::hash(&b))
    }
    fn overhead(self) -> usize {
        40 + 64
            + if self.protection == Protection::HmacSha256 {
                16
            } else {
                0
            }
    }
    /// Maximum complete upper recovery/control record in this fixed packet policy.
    /// Includes no native-delivery or MUX admission authority.
    pub fn max_record_bytes(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(self.body_limit())
    }
    /// Exact record geometry from the maintained protection and phase format.
    /// Current packet emission uses fixed twenty-byte IPv4 and TCP headers.
    pub fn record_geometry(self) -> Result<RecordGeometry, Error> {
        self.validate()?;
        let datagram = self.datagram([0; 16], 0, Direction::ClientToServer);
        let ip_tcp_bytes = datagram.outer_overhead_bytes;
        let record_overhead_bytes = datagram
            .wire_overhead()
            .checked_add(wire::HEADER)
            .ok_or(Error::Capacity)?;
        let max_record_bytes = usize::from(self.mtu)
            .checked_sub(ip_tcp_bytes)
            .and_then(|n| n.checked_sub(record_overhead_bytes))
            .filter(|n| *n > 0)
            .ok_or(Error::Capacity)?;
        let geometry = RecordGeometry {
            path_mtu: usize::from(self.mtu),
            ip_tcp_bytes,
            record_overhead_bytes,
            max_record_bytes,
        };
        if max_record_bytes != self.body_limit() {
            return Err(Error::Proof);
        }
        geometry.ip_bytes(max_record_bytes)?;
        Ok(geometry)
    }
    fn body_limit(self) -> usize {
        usize::from(self.mtu) - self.overhead() - wire::HEADER
    }
    fn datagram(self, session: [u8; 16], lane: usize, direction: Direction) -> DatagramConfig {
        DatagramConfig {
            context: KeyContext {
                session: SessionId(session),
                direction,
                lane: LaneId(lane as u32),
                generation: KeyGeneration(1),
            },
            cover: CoverProfile::OpenVpnLike,
            protection: self.protection,
            path_mtu: usize::from(self.mtu),
            outer_overhead_bytes: 40,
            max_payload_bytes: usize::from(self.mtu) - self.overhead(),
            max_packets_per_key: self.max_key_packets,
            max_payload_bytes_per_key: self.max_key_bytes,
        }
    }
}
/// Exact maintained raw record geometry; no UDP headers or fictitious surcharge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordGeometry {
    /// Complete original IPv4/TCP packet ceiling.
    pub path_mtu: usize,
    /// Actual fixed IPv4/TCP headers; options are not emitted by this format.
    pub ip_tcp_bytes: usize,
    /// Maintained datagram protection plus authenticated phase header.
    pub record_overhead_bytes: usize,
    /// Maximum complete caller record before either authenticated wrapper.
    pub max_record_bytes: usize,
}
impl RecordGeometry {
    /// Validate one complete caller record and return its exact IP wire cost.
    pub fn ip_bytes(self, record_bytes: usize) -> Result<usize, Error> {
        if record_bytes == 0 || record_bytes > self.max_record_bytes {
            return Err(Error::Capacity);
        }
        record_bytes
            .checked_add(self.record_overhead_bytes)
            .and_then(|n| n.checked_add(self.ip_tcp_bytes))
            .filter(|n| *n <= self.path_mtu)
            .ok_or(Error::Capacity)
    }
}

/// Original pair and fixed packet policy; no post-authentication fallback occurs.
#[derive(Clone, Copy, Debug)]
pub struct PacketPhaseConfig {
    /// Existing complete original authentication/record/message/driver policy.
    pub pair: PairConfig,
    /// Explicit independently authenticated packet phase.
    pub packet: PacketPolicy,
}
/// Explicit first terminal transition/carrier cause or unchanged local backpressure.
#[derive(Clone, Debug)]
pub enum Error {
    /// Invalid or incompatible local profile.
    Configuration,
    /// Original owner/authentication failure.
    Pair(PairError),
    /// Fixed grammar, stage or reserved-field violation.
    Format,
    /// Actual local/peer proofs or immutable owner identity differ.
    Proof,
    /// Finite storage/message allowance is exhausted.
    Capacity,
    /// The original absolute transition or fixed active liveness deadline expired.
    Expired,
    /// A checked offset, nonce, byte count or no-wrap allowance is exhausted.
    Exhausted,
    /// The maintained TLS object failed the exclusive terminal predicate.
    TlsFreeze,
    /// Maintained datagram protection rejected local configuration or use.
    Crypto(l2tunnel_datagram::Error),
    /// Actual I/O category and errno; no physical success is invented.
    Io {
        /// Standard error category.
        kind: io::ErrorKind,
        /// Original platform errno, when present.
        raw_os_error: Option<i32>,
    },
    /// Caller must service/consume existing bounded output before staging more.
    Busy,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "raw packet phase: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<PairError> for Error {
    fn from(e: PairError) -> Self {
        Self::Pair(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io {
            kind: e.kind(),
            raw_os_error: e.raw_os_error(),
        }
    }
}
impl From<l2tunnel_datagram::Error> for Error {
    fn from(e: l2tunnel_datagram::Error) -> Self {
        Self::Crypto(e)
    }
}
/// Exact originals returned only before irreversible bridge attachment.
pub struct PacketStartFailure<I: PacketIo> {
    /// Unpolled original packet owners.
    pub inputs: Box<RawInputs<I>>,
    /// Recoverable local rejection.
    pub error: Error,
}
impl<I: PacketIo> fmt::Debug for PacketStartFailure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketStartFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<I: PacketIo> fmt::Display for PacketStartFailure<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl<I: PacketIo> std::error::Error for PacketStartFailure<I> {}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = ring::digest::Context::new(&ring::digest::SHA256);
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    let mut o = [0; 32];
    o.copy_from_slice(h.finish().as_ref());
    o
}
fn lock<T>(v: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, Error> {
    v.lock().map_err(|_| Error::Proof)
}

// Constructed only by the transaction after every actual local/remote Armed copy.
pub(in crate::handoff) struct ArmedLane {
    shared: super::super::stream::Shared,
    seal: [u8; wire::CONTROL],
}
impl ArmedLane {
    pub(in crate::handoff) fn matches(
        &self,
        handle: &super::super::SwitchHandle,
        seal: &[u8],
    ) -> bool {
        Arc::ptr_eq(&self.shared, &handle.shared) && seal == self.seal
    }
}

/// Upper recovery record type; native frames still require the common MUX policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// Already admitted upper recovery source, retry or repair bytes.
    Data,
    /// Upper recovery feedback; finite carrier control service still applies.
    Feedback,
}
/// Opaque locally staged record identity, scoped to its physical lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordToken(u64);
/// Genuine successful original packet-adapter handoff, not peer delivery.
#[derive(Clone, Copy, Debug)]
pub struct SentRecord {
    /// Physical lane that owned the staged record.
    pub lane: PairLane,
    /// Exact locally issued record identity.
    pub token: RecordToken,
    /// Original successful PacketIo::send completion time.
    pub sent_at: Instant,
}
/// Physical-send observation independent of the carrier's continued liveness.
#[derive(Debug)]
pub struct SentRecordObservation {
    /// One actual whole packet handoff, consumed once even after a terminal error.
    pub sent: Option<SentRecord>,
    /// Original sticky carrier failure; a physical send does not make it success.
    pub failure: Option<Error>,
}
/// One complete authenticated carrier record, not a native-delivery confirmation.
pub struct ReceivedRecord {
    /// Original successful authenticated parse receipt, before bounded retention.
    pub received_at: Instant,
    /// Original physical lane.
    pub lane: PairLane,
    /// Recovery record category.
    pub kind: RecordKind,
    /// Exact protected bytes; bounded by the negotiated carrier body limit.
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests;

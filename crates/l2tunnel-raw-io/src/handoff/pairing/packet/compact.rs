//! Final Records metadata and control grammar, without another data protector.
use super::{Error, PacketPolicy, RecordGeometry};

pub(super) type BootstrapFilter = std::sync::Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Fixed canonical external AAD. IP addresses, ports and checksums are excluded.
pub const AAD_BYTES: usize = 49;

/// Exact registered Records purpose in the explicitly selected carrier namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalKind {
    /// Short-check user data; it grants no peer-retirement or liveness authority.
    Data,
    /// Independently strongly authenticated recovery feedback.
    Feedback,
    /// Independently strongly authenticated session/carrier control.
    Control,
    /// Strong raw Window/Ping/Pong, distinct from upper session management.
    CarrierControl,
}
impl FinalKind {
    /// Classify only the disjoint selected namespace, preserving all 64 reader slots.
    pub fn inspect(bytes: &[u8]) -> Option<Self> {
        match *bytes.first()? {
            0 => Some(Self::Control),
            1 => Some(Self::CarrierControl),
            0x80..=0xbf => Some(Self::Data),
            0xc0..=0xff => Some(Self::Feedback),
            _ => None,
        }
    }
    pub(super) const fn reserve(self) -> u64 {
        match self {
            Self::Data => 8,
            Self::Feedback | Self::Control => 4,
            Self::CarrierControl => 0,
        }
    }
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Data => 1,
            Self::Feedback => 2,
            Self::Control => 3,
            Self::CarrierControl => 4,
        }
    }
}

/// Copied canonical packet metadata, not authentication or a raw-owner capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalMetadata {
    pub(super) context: [u8; 32],
    pub(super) lane: u8,
    pub(super) sender: u8,
    pub(super) kind: FinalKind,
    pub(super) sequence: u32,
    pub(super) acknowledgment: u32,
    pub(super) window: u16,
    pub(super) payload_bytes: u16,
}
impl FinalMetadata {
    /// Canonical same-packet AAD for the sole Records protection operation.
    /// Mutable/NAT-translated addresses and checksums never create circular AAD.
    pub fn aad(self) -> [u8; AAD_BYTES] {
        let mut out = [0; AAD_BYTES];
        out[..32].copy_from_slice(&self.context);
        out[32..35].copy_from_slice(&[self.lane, self.sender, self.kind.code()]);
        out[35..39].copy_from_slice(&self.sequence.to_be_bytes());
        out[39..43].copy_from_slice(&self.acknowledgment.to_be_bytes());
        out[43..45].copy_from_slice(&self.window.to_be_bytes());
        out[45..47].copy_from_slice(&0x18u16.to_be_bytes());
        out[47..49].copy_from_slice(&self.payload_bytes.to_be_bytes());
        out
    }
    /// Actual purpose that must match the successfully opened Records route.
    pub const fn kind(self) -> FinalKind {
        self.kind
    }
    /// Exact whole final Records packet length, excluding the fixed IPv4/TCP headers.
    pub const fn payload_bytes(self) -> usize {
        self.payload_bytes as usize
    }
}

/// Existing raw retirement/liveness requests, carried by strong Records control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalControl {
    /// Advertise the actual retirement snapshot bound by this packet's AAD.
    Window,
    /// Existing bounded liveness challenge.
    Ping([u8; 8]),
    /// Exact response to the existing challenge; not user-data confirmation.
    Pong([u8; 8]),
}
impl FinalControl {
    /// Exact payload bytes inside the runtime's authenticated raw-control union.
    pub const fn encoded_bytes(self) -> usize {
        match self {
            Self::Window => 1,
            Self::Ping(_) | Self::Pong(_) => 9,
        }
    }
    /// Serialize only the selected control arm into caller-owned storage.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let length = self.encoded_bytes();
        if out.len() < length {
            return Err(Error::Capacity);
        }
        out[0] = match self {
            Self::Window => 1,
            Self::Ping(_) => 2,
            Self::Pong(_) => 3,
        };
        if let Self::Ping(value) | Self::Pong(value) = self {
            out[1..9].copy_from_slice(&value);
        }
        Ok(length)
    }
    /// Strict complete control parsing; this alone grants no authentication.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        match input {
            [1] => Ok(Self::Window),
            [2, rest @ ..] if rest.len() == 8 => {
                Ok(Self::Ping(rest.try_into().map_err(|_| Error::Format)?))
            }
            [3, rest @ ..] if rest.len() == 8 => {
                Ok(Self::Pong(rest.try_into().map_err(|_| Error::Format)?))
            }
            _ => Err(Error::Format),
        }
    }
}

/// Result supplied by the trusted runtime after its sole Records verifier runs.
/// Commit it through the existing owner's `commit_final_input` method; copying
/// this value cannot create the original `PacketCarrier` or its packet custody.
pub struct FinalAcceptance<T> {
    pub(super) value: T,
    pub(super) authenticated: bool,
    pub(super) control: Option<FinalControl>,
}
impl<T> FinalAcceptance<T> {
    /// Return the caller's accepted value without changing any raw state.
    pub fn into_value(self) -> T {
        self.value
    }
    /// Accepted upper record with the verifier's actual authentication fact.
    pub fn record(value: T, authenticated: bool) -> Self {
        Self {
            value,
            authenticated,
            control: None,
        }
    }
    /// Accepted strong raw control after its sole Records authentication succeeded.
    pub fn control(value: T, control: FinalControl) -> Self {
        Self {
            value,
            authenticated: true,
            control: Some(control),
        }
    }
}

/// Opaque local reservation for one unchanged final physical packet.
/// No offset, nonce or physical receipt is consumed by preparation alone.
#[derive(Debug)]
pub struct FinalOutputToken {
    pub(super) metadata: FinalMetadata,
    pub(super) end: u64,
    pub(super) control: Option<FinalControl>,
}
impl FinalOutputToken {
    /// Exact canonical metadata to bind in the one Records operation.
    pub const fn metadata(&self) -> FinalMetadata {
        self.metadata
    }
}

/// One bounded untrusted final packet under the original arrival time.
pub struct FinalInput<'a> {
    pub(super) metadata: FinalMetadata,
    pub(super) received_at: tokio::time::Instant,
    pub(super) state: std::sync::MutexGuard<'a, super::gate::GateState>,
    pub(super) index: usize,
}
impl FinalInput<'_> {
    /// Same-packet raw context/fields required by the sole Records verifier.
    pub const fn metadata(&self) -> FinalMetadata {
        self.metadata
    }
    /// Whole selected Records bytes, not an already opened inner packet.
    pub fn bytes(&self) -> &[u8] {
        &self.state.incoming[self.index].body
    }
    /// Original physical receive time; verification does not renew it.
    pub const fn received_at(&self) -> tokio::time::Instant {
        self.received_at
    }
}

impl PacketPolicy {
    /// Final single-protection geometry. Bootstrap retains `record_geometry()`.
    /// The caller's record includes its one Records header/check and algorithm body.
    pub fn final_record_geometry(self) -> Result<RecordGeometry, Error> {
        self.validate()?;
        Ok(RecordGeometry {
            path_mtu: usize::from(self.mtu),
            ip_tcp_bytes: 40,
            record_overhead_bytes: 0,
            max_record_bytes: usize::from(self.mtu) - 40,
        })
    }
}

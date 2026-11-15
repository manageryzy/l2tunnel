//! Standalone OpenVPN-like UDP runtime with full and authenticated paired half lanes.
//! Verified TLS over bounded UDP control, separate protected recovery packets and
//! one supervised fixed-tuple socket owner. No interoperability claim.

mod budget;
mod config;
mod data;
mod driver;
mod heartbeat;
mod native;
mod pair;
pub use native::{
    NativeCarrier, NativeControl, NativeControlState, NativeDrainConfig, NativeFence,
    NativePairControl, NativePairedCarrier, PeerFence, SourceFence, client_connect_native,
    client_pair_native, server_accept_native, server_pair_native,
};
mod runtime;
/// Actual OpenVPN-format reset/TLS control and loss-visible protected data on one UDP socket.
pub mod wire_carrier;
pub use budget::WireStatus;
pub use config::{Config, WireBudget};
pub use pair::{
    ClientPairCredentials, PairControl, PairInfo, PairStatus, PairedCarrier, ServerPairCredentials,
    client_pair, server_pair,
};
pub use runtime::{
    Carrier, ClientCredentials, CloseReceipt, Control, PacketReceiver, PacketSender,
    ServerCredentials, Status, Terminal, client_connect, server_accept,
};
#[cfg(test)]
mod test_wire;
#[cfg(test)]
mod tests;

/// Existing protected packet policy types, independent of any TLS/TCP socket.
pub use l2tunnel_udp::{CoverProfile, KeyGeneration, LaneId, Profile, Protection, Traffic};

/// Runtime/configuration failure, containing no secrets or user packet bytes.
#[derive(Debug)]
pub enum Error {
    /// Invalid, excessive or mismatched local policy.
    Configuration(&'static str),
    /// Pure admission/reliable control failure.
    Control(l2tunnel_udp_control::Error),
    /// Actual TLS/member authentication failure.
    Authentication(l2tunnel_auth::Error),
    /// Protected datagram failure.
    Datagram(l2tunnel_datagram::Error),
    /// Bounded data recovery failure.
    Recovery(l2tunnel_recovery::RecoveryError),
    /// Socket/stream failure.
    Io(std::io::Error),
    /// A finite operation, inactivity or absolute lease expired.
    Timeout,
    /// A supervised owner has closed or failed.
    Closed,
    /// The configured half lane forbids this user-data direction.
    DirectionDisabled,
    /// Native/upper-layer packet exceeds the negotiated recovery source size.
    PacketTooLarge,
    /// Caller receive buffer cannot hold the retained packet.
    OutputTooSmall,
    /// Close did not drain every owned packet/handoff before its deadline.
    IncompleteClose,
    /// Required retained reservations or native proofs have not drained yet.
    Busy,
}
impl std::fmt::Display for Error {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "standalone UDP runtime: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<l2tunnel_udp_control::Error> for Error {
    fn from(value: l2tunnel_udp_control::Error) -> Self {
        Self::Control(value)
    }
}
impl From<l2tunnel_auth::Error> for Error {
    fn from(value: l2tunnel_auth::Error) -> Self {
        Self::Authentication(value)
    }
}
impl From<l2tunnel_datagram::Error> for Error {
    fn from(value: l2tunnel_datagram::Error) -> Self {
        Self::Datagram(value)
    }
}
impl From<l2tunnel_recovery::RecoveryError> for Error {
    fn from(value: l2tunnel_recovery::RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

//! Runtime-owned same-socket bootstrap and existing-member authentication.
//!
//! These owners perform no device setup or implicit client/profile selection.
//! A sole data/control reader retains the returned bounded final-flight tails.

/// Explicit bounded control backends under the existing common secure session.
pub mod control;
/// Fixed-size non-secret pre-ready observations; never protocol authority.
pub mod diagnostics;
/// Original connected UDP admission, maintained Noise and bootstrap custody.
pub mod establish;
/// Genuine maintained compatibility carriers and their explicit acceptance boundaries.
pub mod maintained;
/// Bounded ownership of original TLS/QUIC I/O through the Common handoff.
pub mod maintained_io;
/// Actual existing-member proof and authenticated acceptance on that same socket.
pub mod member;
/// Single original UDP/OpenVPN owner with explicit physical-send completion tickets.
pub mod original_datagram;
// Portable same-owner raw I/O; actual packet opening remains platform-specific.
#[path = "transport_raw_buffer_metrics.rs"]
pub(crate) mod raw_buffer_metrics;
mod raw_carrier_io;
/// Native forwarding and fixed authenticated control on the original socket.
pub mod transport;

#[cfg(test)]
mod diagnostics_tests;

/// The precise local send boundary used for custody and recovery timing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SendBoundary {
    /// A complete UDP/raw packet was accepted by the original socket/PacketIo.
    #[default]
    SocketAccepted,
    /// The original maintained TLS stream accepted and flushed a complete frame.
    TlsStreamFlushed,
    /// Quinn accepted the DATAGRAM; scheduling and UDP transmission remain downstream.
    QuicDatagramAccepted,
}

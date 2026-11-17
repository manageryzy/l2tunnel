//! Runtime-owned same-socket bootstrap and existing-member authentication.
//!
//! These owners perform no device setup or implicit client/profile selection.
//! A sole data/control reader retains the returned bounded final-flight tails.

/// Explicit bounded control backends under the existing common secure session.
#[cfg(unix)]
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
// Portable same-owner raw I/O; native forwarding remains Unix-gated below.
mod raw_carrier_io;
/// Unix native forwarding and fixed authenticated control on the original socket.
#[cfg(unix)]
pub mod transport;

#[cfg(test)]
mod diagnostics_tests;

/// Same-owner fresh-DH adapter; selected Driver service integration remains pending.
#[cfg(unix)]
#[allow(dead_code)]
// Pure runtime adapter is exercised separately; no periodic default is installed.
pub mod session_refresh;

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

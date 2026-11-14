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
/// Actual existing-member proof and authenticated acceptance on that same socket.
pub mod member;
/// Unix native forwarding and fixed authenticated control on the original socket.
#[cfg(unix)]
pub mod transport;

#[cfg(test)]
mod diagnostics_tests;

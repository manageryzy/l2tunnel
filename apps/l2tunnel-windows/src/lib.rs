//! Windows configuration and reusable frontend components.
//!
//! The provisioned UDP Common worker shares its service owner with Android and Linux.
/// Strict, side-effect-free requested configuration parsing and capability checks.
pub mod cli;
/// Bounded text-only output, independent of tunnel ownership.
pub mod diagnostics;
/// Bounded local command parsing, without an installed service executor.
pub mod input;
/// Actual Windows execution capability reporting.
#[cfg(windows)]
pub mod native;
/// Joined blocking setup ownership, independent of a tunnel implementation.
pub mod setup;
/// Private native worker launched by the local GUI host.
pub mod worker;

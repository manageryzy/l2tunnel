//! Windows configuration and reusable frontend components.
//!
//! The Windows service host serves the shared service owner on the local API
//! named pipe (docs/modules/windows-local-service.md).
/// Strict, side-effect-free requested configuration parsing and capability checks.
pub mod cli;
/// Bounded text-only output, independent of tunnel ownership.
pub mod diagnostics;
/// Local service host: one service owner serving the local API pipe.
pub mod host;
/// Bounded local command parsing, without an installed service executor.
pub mod input;
/// Actual Windows execution capability reporting.
#[cfg(windows)]
pub mod native;
/// Windows service install/uninstall and service-control-manager entry.
pub mod service;
/// Joined blocking setup ownership, independent of a tunnel implementation.
pub mod setup;

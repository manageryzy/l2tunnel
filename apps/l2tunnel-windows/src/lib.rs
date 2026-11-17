//! Windows configuration and reusable frontend components.
//!
//! The application has no current Common service binding. Parsing and these
//! independently tested helpers do not establish a native Windows tunnel.
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

//! Windows foreground presentation over the same portable client/service owner.
/// Strict, side-effect-free command parsing and bounded credential input.
pub mod cli;
/// Foreground cancellation and observation through the existing shared service.
#[cfg(any(windows, test))]
pub(crate) mod foreground;
/// Actual Windows device ownership and console cancellation.
#[cfg(windows)]
pub mod native;

#[cfg(any(windows, test))]
mod setup;

#[cfg(any(windows, test))]
mod diagnostics;

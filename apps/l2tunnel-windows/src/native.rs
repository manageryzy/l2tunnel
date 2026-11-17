//! Explicit Windows execution capability boundary.
use crate::cli::Plan;
use std::io;

/// Refuse the unimplemented Common service binding before opening native owners.
///
/// The Wintun device component remains available in `l2tunnel-platform-windows`.
/// Its existence does not provide a Windows application tunnel or service.
pub fn execute(plan: Plan) -> io::Result<()> {
    plan.check_runtime_support()
}

//! Shared CLI frontend for local service status and coordinated mode changes.
fn main() -> std::process::ExitCode {
    l2tunnel_client_core::cli::main_entry(std::env::args().skip(1))
}

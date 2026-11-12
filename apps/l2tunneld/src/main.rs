//! Linux-capable headless client entry point using the shared lifecycle.
fn main() -> std::process::ExitCode {
    l2tunnel_client_core::cli::main_entry(std::env::args().skip(1))
}

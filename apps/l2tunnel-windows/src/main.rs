//! Windows configuration and explicit execution capability reporting.
use l2tunnel_windows::cli::{self, Command};
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn execute() -> io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Some(command) = l2tunnel_windows::service::parse(&arguments) {
        return l2tunnel_windows::service::execute(command?);
    }
    match cli::parse(&arguments)? {
        Command::Help => writeln!(io::stdout().lock(), "{}", cli::HELP),
        Command::Version => writeln!(
            io::stdout().lock(),
            "l2tunnel-windows {}",
            env!("CARGO_PKG_VERSION")
        ),
        Command::Plan => writeln!(
            io::stdout().lock(),
            "Windows service host (cross-compiled; not yet executed on native Windows) serves local API v1/v4/v5 on a named pipe with a proposed DACL and owns a provisioned original UDP Common tunnel with a pinned Wintun L3 device. Windows TAP, alternate carriers, credential vault, event logging, sleep/recovery and native hardware qualification remain open.\n{}",
            l2tunnel::IMPLEMENTATION_STATUS
        ),
        Command::Connect(plan) => {
            #[cfg(windows)]
            {
                l2tunnel_windows::native::execute(*plan)
            }
            #[cfg(not(windows))]
            {
                plan.check_runtime_support()
            }
        }
    }
}
fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "l2tunnel-windows: {error}");
            ExitCode::from(2)
        }
    }
}

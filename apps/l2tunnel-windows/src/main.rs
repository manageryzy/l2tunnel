//! Windows configuration and explicit execution capability reporting.
use l2tunnel_windows::cli::{self, Command};
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn execute() -> io::Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse(&arguments)? {
        Command::Help => writeln!(io::stdout().lock(), "{}", cli::HELP),
        Command::Version => writeln!(
            io::stdout().lock(),
            "l2tunnel-windows {}",
            env!("CARGO_PKG_VERSION")
        ),
        Command::Plan => writeln!(
            io::stdout().lock(),
            "Windows Common client/service binding: unsupported and pending. The obsolete managed TCP/TLS foreground path has been removed. Wintun device/configuration and bounded helper components remain available; they do not establish a tunnel. Windows service/named pipes, TAP L2, credential vault, sleep/recovery, and native carrier/mode qualification remain open.\n{}",
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
